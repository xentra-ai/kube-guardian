package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
)

// `kguardian compute findings` is a report over GET /compute/findings. The
// table must be stable (critical -> high -> medium, then victim) and the
// CULPRIT / SHARE columns must render every culprit kind the broker emits;
// `-o json` must pass the broker body through untouched so fields this CLI
// build does not know about still reach the operator.

func strp(s string) *string   { return &s }
func f64p(f float64) *float64 { return &f }

func finding(sev, kind, ns, pod, container string, culprit *api.ComputeFindingCulprit, msg string) api.ComputeFinding {
	return api.ComputeFinding{
		Kind:     kind,
		Severity: sev,
		Victim:   api.ComputeFindingVictim{PodUID: "uid-" + pod, Namespace: ns, PodName: pod, Container: container, ContainerUID: "uid-" + pod + "/" + container, Node: "worker-3"},
		Culprit:  culprit,
		Message:  msg,
	}
}

// tableRows splits rendered output into whitespace-collapsed rows, skipping
// the header, so assertions don't depend on tabwriter padding.
func tableRows(t *testing.T, out string) [][]string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 1 || !strings.HasPrefix(lines[0], "SEVERITY") {
		t.Fatalf("missing header, got:\n%s", out)
	}
	var rows [][]string
	for _, l := range lines[1:] {
		rows = append(rows, strings.Fields(l))
	}
	return rows
}

func TestRenderComputeFindingsTable_HeaderAndColumns(t *testing.T) {
	var buf bytes.Buffer
	err := renderComputeFindingsTable(&buf, []api.ComputeFinding{
		finding("high", "noisy-neighbor", "payments", "api-7c9", "api",
			&api.ComputeFindingCulprit{Kind: "pod", Ref: "batch/etl-1-x/worker", Namespace: strp("batch"), PodName: strp("etl-1-x"), BlameShare: f64p(0.71)},
			"payments/api is starved for CPU by batch/etl-1-x (71% of its wait)"),
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	header := strings.Fields(strings.SplitN(out, "\n", 2)[0])
	want := []string{"SEVERITY", "KIND", "VICTIM", "CULPRIT", "SHARE", "MESSAGE"}
	if strings.Join(header, " ") != strings.Join(want, " ") {
		t.Errorf("header: want %v, got %v", want, header)
	}
	rows := tableRows(t, out)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d:\n%s", len(rows), out)
	}
	r := rows[0]
	if r[0] != "high" || r[1] != "noisy-neighbor" || r[2] != "payments/api-7c9" || r[3] != "batch/etl-1-x" || r[4] != "71%" {
		t.Errorf("row columns wrong: %v", r)
	}
	if !strings.Contains(out, "payments/api is starved for CPU by batch/etl-1-x (71% of its wait)") {
		t.Errorf("message must be rendered verbatim:\n%s", out)
	}
}

func TestRenderComputeFindingsTable_SortsCriticalHighMediumThenVictim(t *testing.T) {
	in := []api.ComputeFinding{
		finding("medium", "cpu-throttled", "zeta", "z-pod", "app", nil, "m1"),
		finding("high", "noisy-neighbor", "beta", "b-pod", "app", &api.ComputeFindingCulprit{Kind: "kernel", Ref: "kworker"}, "h2"),
		finding("critical", "memory-pressure", "omega", "o-pod", "app", &api.ComputeFindingCulprit{Kind: "pod", Namespace: strp("x"), PodName: strp("hog"), BlameShare: f64p(0.5)}, "c1"),
		finding("high", "cpu-contended", "alpha", "a-pod", "app", nil, "h1"),
		finding("medium", "memory-limit-thrash", "alpha", "a-pod", "app", nil, "m0"),
	}
	// Keep a copy: render must not reorder the caller's slice.
	orig := make([]api.ComputeFinding, len(in))
	copy(orig, in)

	var buf bytes.Buffer
	if err := renderComputeFindingsTable(&buf, in); err != nil {
		t.Fatalf("render: %v", err)
	}
	rows := tableRows(t, buf.String())
	var got []string
	for _, r := range rows {
		got = append(got, r[0]+" "+r[2])
	}
	want := []string{
		"critical omega/o-pod",
		"high alpha/a-pod",
		"high beta/b-pod",
		"medium alpha/a-pod",
		"medium zeta/z-pod",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("order:\n want %v\n  got %v", want, got)
	}
	for i := range in {
		if in[i].Message != orig[i].Message {
			t.Errorf("input slice was reordered at %d", i)
		}
	}
}

func TestFormatCulprit(t *testing.T) {
	cases := []struct {
		name string
		in   *api.ComputeFindingCulprit
		want string
	}{
		{"nil culprit", nil, "-"},
		{"pod with ns", &api.ComputeFindingCulprit{Kind: "pod", Ref: "batch/etl-1-x/worker", Namespace: strp("batch"), PodName: strp("etl-1-x")}, "batch/etl-1-x"},
		{"pod without ns falls back to name", &api.ComputeFindingCulprit{Kind: "pod", PodName: strp("etl-1-x")}, "etl-1-x"},
		{"pod with only ref", &api.ComputeFindingCulprit{Kind: "pod", Ref: "batch/etl-1-x/worker"}, "batch/etl-1-x/worker"},
		{"system unit strips slice path", &api.ComputeFindingCulprit{Kind: "system", Ref: "system.slice/kubelet.service"}, "system:kubelet.service"},
		{"system bare unit", &api.ComputeFindingCulprit{Kind: "system", Ref: "containerd.service"}, "system:containerd.service"},
		{"system empty ref", &api.ComputeFindingCulprit{Kind: "system"}, "system"},
		{"kernel", &api.ComputeFindingCulprit{Kind: "kernel", Ref: "kworker/u16:3"}, "kernel"},
		{"unknown kind uses ref", &api.ComputeFindingCulprit{Kind: "unknown", Ref: "cgroup:4242"}, "cgroup:4242"},
		{"unknown kind no ref", &api.ComputeFindingCulprit{Kind: "unknown"}, "-"},
	}
	for _, tc := range cases {
		if got := formatCulprit(tc.in); got != tc.want {
			t.Errorf("%s: want %q, got %q", tc.name, tc.want, got)
		}
	}
}

func TestFormatShare(t *testing.T) {
	cases := []struct {
		name string
		in   *api.ComputeFindingCulprit
		want string
	}{
		{"nil culprit", nil, "-"},
		{"nil share", &api.ComputeFindingCulprit{Kind: "pod"}, "-"},
		{"0.71 rounds to 71%", &api.ComputeFindingCulprit{BlameShare: f64p(0.71)}, "71%"},
		{"0.405 rounds to 41%", &api.ComputeFindingCulprit{BlameShare: f64p(0.405)}, "41%"},
		{"1.0 is 100%", &api.ComputeFindingCulprit{BlameShare: f64p(1.0)}, "100%"},
		{"0 is 0%", &api.ComputeFindingCulprit{BlameShare: f64p(0)}, "0%"},
	}
	for _, tc := range cases {
		if got := formatShare(tc.in); got != tc.want {
			t.Errorf("%s: want %q, got %q", tc.name, tc.want, got)
		}
	}
}

func TestFormatMillis_NullIsDash(t *testing.T) {
	if got := formatMillis(nil); got != "-" {
		t.Errorf("nil: want -, got %q", got)
	}
	if got := formatMillis(f64p(1900.4)); got != "1900m" {
		t.Errorf("1900.4: want 1900m, got %q", got)
	}
}

func TestComputeFinding_DecodesNullCulpritUsage(t *testing.T) {
	// The broker sends cpu_usage_millis: null for a culprit that opted out of
	// sampling. It must decode to nil (not 0, not an error) so the CLI never
	// reports a fabricated usage figure.
	var resp api.ComputeFindingsResponse
	if err := json.Unmarshal([]byte(brokerFindingsBody), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var nullUsage *api.ComputeFindingCulprit
	for _, f := range resp.Findings {
		if f.Victim.PodName == "checkout-1" {
			nullUsage = f.Culprit
		}
	}
	if nullUsage == nil {
		t.Fatal("fixture lost the null-usage culprit")
	}
	if nullUsage.CPUUsageMillis != nil {
		t.Errorf("cpu_usage_millis null must decode to nil, got %v", *nullUsage.CPUUsageMillis)
	}
	if nullUsage.CPURequestMillis != nil {
		t.Errorf("cpu_request_millis null must decode to nil")
	}
	if nullUsage.BlameShare == nil || *nullUsage.BlameShare != 0.9 {
		t.Errorf("blame_share must still decode alongside null usage")
	}
	if got := formatMillis(nullUsage.CPUUsageMillis); got != "-" {
		t.Errorf("null usage must render as -, got %q", got)
	}
}

func TestRenderComputeFindingsTable_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := renderComputeFindingsTable(&buf, nil); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "No compute findings." {
		t.Errorf("empty result: got %q", buf.String())
	}
}

// brokerFixture serves /compute/findings and records the query it received.
const brokerFindingsBody = `{"findings":[
  {"kind":"cpu-throttled","severity":"medium",
   "victim":{"pod_uid":"u1","namespace":"payments","pod_name":"api-7c9","container":"api","container_uid":"u1/api","node":"worker-3"},
   "culprit":null,
   "evidence":{"window_minutes":5,"throttled_ratio":0.42,"some_future_field":true},
   "first_seen":"2026-09-10T02:36:05Z","last_seen":"2026-09-10T02:41:05Z",
   "message":"payments/api is throttled 42% of CFS periods against its 0.5-core limit"},
  {"kind":"noisy-neighbor","severity":"high",
   "victim":{"pod_uid":"u1","namespace":"payments","pod_name":"api-7c9","container":"api","container_uid":"u1/api","node":"worker-3"},
   "culprit":{"kind":"system","ref":"system.slice/kubelet.service","pod_uid":null,"namespace":null,"pod_name":null,"container_uid":null,"blame_share":0.58,"cpu_usage_millis":900.0,"cpu_request_millis":null},
   "evidence":{"window_minutes":5},
   "first_seen":"2026-09-10T02:36:05Z","last_seen":"2026-09-10T02:41:05Z",
   "message":"payments/api is starved for CPU by kubelet.service (58% of its wait)"},
  {"kind":"noisy-neighbor","severity":"critical",
   "victim":{"pod_uid":"u3","namespace":"payments","pod_name":"checkout-1","container":"web","container_uid":"u3/web","node":"worker-3"},
   "culprit":{"kind":"pod","ref":"batch/etl-1/worker","pod_uid":"u9","namespace":"batch","pod_name":"etl-1","container_uid":"u9/worker","blame_share":0.9,"cpu_usage_millis":null,"cpu_request_millis":null},
   "evidence":{"window_minutes":5},
   "first_seen":"2026-09-10T02:36:05Z","last_seen":"2026-09-10T02:41:05Z",
   "message":"payments/checkout-1 is starved for CPU by batch/etl-1 (90% of its wait); etl-1 opted out of compute sampling so its usage is unknown"}
],"future_top_level":"kept"}`

func newBrokerFixture(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/compute/findings" {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(brokerFindingsBody))
	}))
	t.Cleanup(srv.Close)
	orig := api.BrokerBaseURL
	api.BrokerBaseURL = srv.URL
	t.Cleanup(func() { api.BrokerBaseURL = orig })
	return srv, &gotQuery
}

func TestFetchAndRenderComputeFindings_JSONPassthrough(t *testing.T) {
	_, gotQuery := newBrokerFixture(t)
	var buf, errBuf bytes.Buffer
	if err := fetchAndRenderComputeFindings("payments", "worker-3", "json", &buf, &errBuf); err != nil {
		t.Fatalf("fetch/render: %v", err)
	}
	if *gotQuery != "namespace=payments&node=worker-3" {
		t.Errorf("query: want namespace=payments&node=worker-3, got %q", *gotQuery)
	}
	// Byte-for-byte semantic equality with the broker body, unknown fields included.
	var want, got any
	if err := json.Unmarshal([]byte(brokerFindingsBody), &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	wantB, _ := json.Marshal(want)
	gotB, _ := json.Marshal(got)
	if string(wantB) != string(gotB) {
		t.Errorf("json output drifted from broker body:\n want %s\n  got %s", wantB, gotB)
	}
	if !strings.Contains(buf.String(), `"future_top_level": "kept"`) || !strings.Contains(buf.String(), `"some_future_field": true`) {
		t.Errorf("unknown fields must pass through:\n%s", buf.String())
	}
}

func TestFetchAndRenderComputeFindings_TableFromBroker(t *testing.T) {
	_, gotQuery := newBrokerFixture(t)
	var buf, errBuf bytes.Buffer
	if err := fetchAndRenderComputeFindings("", "", "table", &buf, &errBuf); err != nil {
		t.Fatalf("fetch/render: %v", err)
	}
	if *gotQuery != "" {
		t.Errorf("cluster scope must send no query, got %q", *gotQuery)
	}
	if errBuf.Len() != 0 {
		t.Errorf("no notice expected when neither truncated nor history_disabled, got %q", errBuf.String())
	}
	rows := tableRows(t, buf.String())
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d:\n%s", len(rows), buf.String())
	}
	// critical (null cpu_usage_millis culprit) first: share still renders, nothing panics.
	if rows[0][0] != "critical" || rows[0][3] != "batch/etl-1" || rows[0][4] != "90%" {
		t.Errorf("row 0: %v", rows[0])
	}
	// high before medium; system culprit rendered as system:<unit> with share.
	if rows[1][0] != "high" || rows[1][3] != "system:kubelet.service" || rows[1][4] != "58%" {
		t.Errorf("row 1: %v", rows[1])
	}
	if rows[2][0] != "medium" || rows[2][3] != "-" || rows[2][4] != "-" {
		t.Errorf("row 2: %v", rows[2])
	}
}

func TestFetchAndRenderComputeFindings_NamespaceOnlyQuery(t *testing.T) {
	_, gotQuery := newBrokerFixture(t)
	var buf, errBuf bytes.Buffer
	if err := fetchAndRenderComputeFindings("payments", "", "table", &buf, &errBuf); err != nil {
		t.Fatalf("fetch/render: %v", err)
	}
	if *gotQuery != "namespace=payments" {
		t.Errorf("query: want namespace=payments, got %q", *gotQuery)
	}
}

func TestFetchAndRenderComputeFindings_BrokerErrorIsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	orig := api.BrokerBaseURL
	api.BrokerBaseURL = srv.URL
	t.Cleanup(func() { api.BrokerBaseURL = orig })

	var buf, errBuf bytes.Buffer
	err := fetchAndRenderComputeFindings("", "", "table", &buf, &errBuf)
	if err == nil {
		t.Fatal("a broker 500 must surface as an error, not an empty report")
	}
	if buf.Len() != 0 {
		t.Errorf("nothing should be written on error, got %q", buf.String())
	}
}

func TestComputeFindingsCmd_RegisteredWithFlags(t *testing.T) {
	// The command must hang off `compute` (kubectl kguardian compute findings)
	// and expose --node and -o/--output; -n comes from the global kube flags.
	found := false
	for _, c := range rootCmd.Commands() {
		if c.Name() == "compute" {
			found = true
			sub, _, err := c.Find([]string{"findings"})
			if err != nil || sub == nil || sub.Name() != "findings" {
				t.Fatalf("compute findings subcommand missing: %v", err)
			}
			if sub.Flags().Lookup("node") == nil {
				t.Error("--node flag missing")
			}
			if f := sub.Flags().Lookup("output"); f == nil || f.Shorthand != "o" || f.DefValue != "table" {
				t.Errorf("-o/--output flag wrong: %+v", f)
			}
			if sub.Flags().Lookup("namespace") == nil && rootCmd.PersistentFlags().Lookup("namespace") == nil {
				t.Error("-n/--namespace must be reachable from compute findings")
			}
		}
	}
	if !found {
		t.Fatal("compute command not registered on root")
	}
}

// serveFindingsBody points the broker client at a server returning body.
func serveFindingsBody(t *testing.T, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	orig := api.BrokerBaseURL
	api.BrokerBaseURL = srv.URL
	t.Cleanup(func() { api.BrokerBaseURL = orig })
}

func TestFetchAndRenderComputeFindings_HistoryDisabledNotice(t *testing.T) {
	// retentionDays=0 means the engine has no window: an empty list here is a
	// configuration state, not a clean bill of health. The operator must be
	// told, on stderr (stdout stays a clean table), and the exit code stays 0.
	serveFindingsBody(t, `{"findings":[],"history_disabled":true,"victims_evaluated":0}`)
	var out, errOut bytes.Buffer
	if err := fetchAndRenderComputeFindings("", "", "table", &out, &errOut); err != nil {
		t.Fatalf("history_disabled must not be an error (exit 0): %v", err)
	}
	if strings.TrimSpace(errOut.String()) != historyDisabledNotice {
		t.Errorf("stderr: want %q, got %q", historyDisabledNotice, errOut.String())
	}
	if !strings.Contains(errOut.String(), "compute.history.retentionDays is 0") {
		t.Errorf("notice must name the values key to flip")
	}
	if strings.TrimSpace(out.String()) != "No compute findings." {
		t.Errorf("stdout should still carry the (empty) report, got %q", out.String())
	}
}

func TestFetchAndRenderComputeFindings_TruncatedNotice(t *testing.T) {
	serveFindingsBody(t, `{"findings":[
  {"kind":"cpu-throttled","severity":"medium","victim":{"namespace":"a","pod_name":"p","container":"c"},"culprit":null,"message":"m"}
],"truncated":true,"victims_evaluated":500}`)
	var out, errOut bytes.Buffer
	if err := fetchAndRenderComputeFindings("", "", "table", &out, &errOut); err != nil {
		t.Fatalf("truncated must not be an error (exit 0): %v", err)
	}
	want := "Findings evaluated for the first 500 victims (victims_evaluated); narrow with -n or --node."
	if strings.TrimSpace(errOut.String()) != want {
		t.Errorf("stderr: want %q, got %q", want, errOut.String())
	}
	if rows := tableRows(t, out.String()); len(rows) != 1 {
		t.Errorf("table must still render the findings that were evaluated, got %d rows", len(rows))
	}
}

func TestFetchAndRenderComputeFindings_JSONModeCarriesNoticesAsFields(t *testing.T) {
	// JSON is raw passthrough: the flags reach the caller as fields, and
	// nothing is written to stderr so `-o json | jq` pipelines stay clean.
	serveFindingsBody(t, `{"findings":[],"truncated":true,"victims_evaluated":7,"history_disabled":true}`)
	var out, errOut bytes.Buffer
	if err := fetchAndRenderComputeFindings("", "", "json", &out, &errOut); err != nil {
		t.Fatalf("json: %v", err)
	}
	if errOut.Len() != 0 {
		t.Errorf("json mode must not print notices to stderr, got %q", errOut.String())
	}
	var got api.ComputeFindingsResponse
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	if !got.Truncated || got.VictimsEvaluated != 7 || !got.HistoryDisabled {
		t.Errorf("flags lost in passthrough: %+v", got)
	}
}
