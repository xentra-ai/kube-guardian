package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/kguardian-dev/kguardian/advisor/pkg/k8s"
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// computeCmd groups the live compute-gauge / noisy-neighbour commands. Read-only:
// nothing under `compute` generates or applies a resource.
var computeCmd = &cobra.Command{
	Use:   "compute",
	Short: "Inspect live compute gauges and noisy-neighbour findings",
	Long: `Read-only views over the compute telemetry the kguardian controller
samples from every pod's cgroup (CPU usage vs request/limit, CFS throttling,
PSI pressure, memory working set) and, when the scheduler contention probe
is loaded, which cgroups pre-empt which.

  findings   list the broker's compute findings (noisy-neighbor, cpu-throttled,
             cpu-contended, memory-pressure, memory-limit-thrash)

Findings are computed broker-side, so this command, the UI and the assistant
tools always agree. Nothing here changes the cluster.`,
}

var (
	computeFindingsNode   string
	computeFindingsOutput string
)

var computeFindingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "List compute findings (noisy neighbours, throttling, memory pressure)",
	Long: `List the broker's current compute findings.

Each finding names a VICTIM container, a KIND, and — for the cross-container
kinds — the CULPRIT cgroup the broker blames and its SHARE: the culprit's
share of the victim's CPU wait (noisy-neighbor), or of the node's memory
overage (memory-pressure). Self-inflicted kinds have no culprit and no share:

  noisy-neighbor       victim starved for CPU by a named pod or system unit
  cpu-contended        victim starved, no single dominant culprit
  cpu-throttled        victim hitting its own CPU limit (no culprit; raise the limit)
  memory-pressure      node under memory pressure, culprit named
  memory-limit-thrash  victim thrashing under its own memory limit (no culprit)

Scope defaults to the whole cluster. Pass -n/--namespace to restrict to
victims in one namespace (culprits may still live elsewhere) and/or --node to
one node. Rows are sorted critical -> high -> medium, then by victim.

This is a report, not a gate: the exit code is 0 whether or not findings
exist. Use -o json for the broker's raw response.

Examples:
  kubectl kguardian compute findings
  kubectl kguardian compute findings -n payments
  kubectl kguardian compute findings --node worker-3 -o json`,
	Args: cobra.NoArgs,
	RunE: runComputeFindings,
}

func init() {
	rootCmd.AddCommand(computeCmd)
	computeCmd.AddCommand(computeFindingsCmd)
	computeFindingsCmd.Flags().StringVar(&computeFindingsNode, "node", "", "Only findings whose victim runs on this node")
	computeFindingsCmd.Flags().StringVarP(&computeFindingsOutput, "output", "o", "table", "Output format: table or json")
}

func runComputeFindings(cmd *cobra.Command, _ []string) error {
	output := strings.ToLower(strings.TrimSpace(computeFindingsOutput))
	if output != "table" && output != "json" {
		return fmt.Errorf("invalid --output %q: must be table or json", computeFindingsOutput)
	}

	// Only scope by namespace when the user asked for one: the kubeconfig
	// context's default namespace must not silently hide cluster-wide findings.
	namespace := ""
	if cmd.Flags().Changed("namespace") {
		namespace, _ = cmd.Flags().GetString("namespace")
	}

	config, ok := cmd.Context().Value(k8s.ConfigKey).(*k8s.Config)
	if !ok || config == nil {
		return fmt.Errorf("failed to retrieve Kubernetes configuration")
	}

	// Reach the broker through the same port-forward every other CLI command uses.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stopChan, errChan, done := k8s.PortForward(config, brokerNamespace, brokerService)
	defer close(stopChan)
	select {
	case <-done:
		log.Debug().Msg("Port forwarding setup completed")
	case err := <-errChan:
		return fmt.Errorf("setting up broker port-forward: %w", err)
	case <-ctx.Done():
		return fmt.Errorf("timeout waiting for broker port-forward")
	}

	return fetchAndRenderComputeFindings(namespace, computeFindingsNode, output, os.Stdout, os.Stderr)
}

// Operator notices for the table mode. Both go to stderr so a piped table
// stays clean, and neither changes the exit code: this is a report.
const (
	historyDisabledNotice = "Compute findings are unavailable: history retention is disabled on the broker (compute.history.retentionDays is 0)."
	truncatedNoticeFmt    = "Findings evaluated for the first %d victims (victims_evaluated); narrow with -n or --node."
)

// fetchAndRenderComputeFindings is the testable core: fetch via the broker
// client, then render as a table (stdout) plus any history_disabled /
// truncated notice (stderr), or pass the broker's JSON through verbatim
// (re-indented, notices included as fields). A fetch failure is an error; an
// empty result is not.
func fetchAndRenderComputeFindings(namespace, node, output string, w, errw io.Writer) error {
	resp, raw, err := api.GetComputeFindings(namespace, node)
	if err != nil {
		return fmt.Errorf("fetching compute findings: %w", err)
	}
	if output == "json" {
		var buf bytes.Buffer
		if err := json.Indent(&buf, raw, "", "  "); err != nil {
			// Not valid JSON we can re-indent (should be unreachable after a
			// successful decode) — emit the bytes as received.
			buf.Reset()
			buf.Write(raw)
		}
		buf.WriteByte('\n')
		_, err := w.Write(buf.Bytes())
		return err
	}
	if resp.HistoryDisabled {
		if _, err := fmt.Fprintln(errw, historyDisabledNotice); err != nil {
			return err
		}
	}
	if err := renderComputeFindingsTable(w, resp.Findings); err != nil {
		return err
	}
	if resp.Truncated {
		if _, err := fmt.Fprintf(errw, truncatedNoticeFmt+"\n", resp.VictimsEvaluated); err != nil {
			return err
		}
	}
	return nil
}

// severityRank orders critical before high before medium; anything the
// broker adds later sorts last rather than breaking the command.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	default:
		return 3
	}
}

// sortComputeFindings orders rows critical -> high -> medium, then by victim
// (namespace/pod, then container), then kind, for a deterministic table.
func sortComputeFindings(findings []api.ComputeFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if va, vb := formatVictim(a.Victim), formatVictim(b.Victim); va != vb {
			return va < vb
		}
		if a.Victim.Container != b.Victim.Container {
			return a.Victim.Container < b.Victim.Container
		}
		return a.Kind < b.Kind
	})
}

func formatVictim(v api.ComputeFindingVictim) string {
	if v.Namespace == "" {
		return v.PodName
	}
	return v.Namespace + "/" + v.PodName
}

// formatCulprit renders the CULPRIT column: `ns/pod` for a pod, `system:<unit>`
// for a systemd unit (last path segment of the cgroup ref, e.g.
// system.slice/kubelet.service -> system:kubelet.service), `kernel`, or `-`
// when the finding has no culprit.
func formatCulprit(c *api.ComputeFindingCulprit) string {
	if c == nil {
		return "-"
	}
	switch c.Kind {
	case "pod":
		if c.PodName != nil && *c.PodName != "" {
			if c.Namespace != nil && *c.Namespace != "" {
				return *c.Namespace + "/" + *c.PodName
			}
			return *c.PodName
		}
		if c.Ref != "" {
			return c.Ref
		}
		return "-"
	case "system":
		unit := c.Ref
		if i := strings.LastIndex(unit, "/"); i >= 0 {
			unit = unit[i+1:]
		}
		if unit == "" {
			return "system"
		}
		return "system:" + unit
	case "kernel":
		return "kernel"
	default:
		if c.Ref != "" {
			return c.Ref
		}
		return "-"
	}
}

// formatMillis renders an optional millicore value (e.g. culprit
// cpu_usage_millis) as "1900m", or `-` when the broker sent null — an
// opted-out culprit has a blame share but no usage figure. Used by the
// debug log line; the table has no usage column by contract.
func formatMillis(v *float64) string {
	if v == nil || math.IsNaN(*v) {
		return "-"
	}
	return fmt.Sprintf("%dm", int(math.Round(*v)))
}

// formatShare renders blame_share (a 0..1 fraction) as a whole percent, or `-`.
// What the fraction is a share OF depends on the kind: the victim's CPU wait
// for noisy-neighbor, the node's memory overage for memory-pressure.
func formatShare(c *api.ComputeFindingCulprit) string {
	if c == nil || c.BlameShare == nil || math.IsNaN(*c.BlameShare) {
		return "-"
	}
	return fmt.Sprintf("%d%%", int(math.Round(*c.BlameShare*100)))
}

// renderComputeFindingsTable writes the SEVERITY KIND VICTIM CULPRIT SHARE
// MESSAGE table. MESSAGE is last so its free text never misaligns a column.
func renderComputeFindingsTable(w io.Writer, findings []api.ComputeFinding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "No compute findings.")
		return err
	}
	rows := make([]api.ComputeFinding, len(findings))
	copy(rows, findings)
	sortComputeFindings(rows)

	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SEVERITY\tKIND\tVICTIM\tCULPRIT\tSHARE\tMESSAGE"); err != nil {
		return err
	}
	for _, f := range rows {
		if f.Culprit != nil {
			log.Debug().Str("victim", formatVictim(f.Victim)).Str("culprit", formatCulprit(f.Culprit)).
				Str("culprit_cpu", formatMillis(f.Culprit.CPUUsageMillis)).Msg("compute finding")
		}
		msg := strings.ReplaceAll(strings.ReplaceAll(f.Message, "\n", " "), "\t", " ")
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Severity, f.Kind, formatVictim(f.Victim), formatCulprit(f.Culprit), formatShare(f.Culprit), msg); err != nil {
			return err
		}
	}
	return tw.Flush()
}
