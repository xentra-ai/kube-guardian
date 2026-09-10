import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { computeQuery, p99, summariseComputeHistory, selectPodFromLatest } from "./compute.js";
import { executeInProcessTool } from "./execute.js";

// --- pure helpers -----------------------------------------------------------

test("computeQuery omits empty / non-positive values and encodes the rest", () => {
  assert.equal(computeQuery({}), "");
  assert.equal(computeQuery({ namespace: "" , node: undefined, minutes: 0 }), "");
  assert.equal(computeQuery({ namespace: "payments" }), "?namespace=payments");
  assert.equal(computeQuery({ node: "worker 3" }), "?node=worker+3");
  assert.equal(computeQuery({ namespace: "a", node: "b", minutes: 5.9 }), "?namespace=a&node=b&minutes=5");
  assert.equal(computeQuery({ minutes: -1 }), "");
  assert.equal(computeQuery({ minutes: Number.NaN }), "");
});

test("p99 is nearest-rank: max for short windows, 99th percentile for long ones", () => {
  assert.equal(p99([]), null);
  assert.equal(p99([7]), 7);
  assert.equal(p99([3, 1, 2]), 3);
  const hundred = Array.from({ length: 100 }, (_, i) => i + 1); // 1..100
  assert.equal(p99(hundred), 99);
  const twoHundred = Array.from({ length: 200 }, (_, i) => i + 1);
  assert.equal(p99(twoHundred), 198);
});

const row = (o: Record<string, unknown>) => ({
  container_uid: "uid-1/api", container: "api", cpu_request_millis: 250, cpu_limit_millis: 500,
  mem_limit: 268435456, mem_request: 134217728, ...o,
});

test("summariseComputeHistory groups per container and derives avg/max/p99, throttle ratio and sums", () => {
  const rows = [
    // out-of-order ts on purpose: the summariser must sort before picking "last"
    row({ ts: "2026-09-10T02:42:00", cpu_usage_millis_avg: 300, cpu_usage_millis_max: 480, cpu_nr_periods: 600, cpu_nr_throttled: 300,
      cpu_psi_some10_max: 31, cpu_psi_full10_max: 4.2, mem_working_set_avg: 200, mem_working_set_max: 220, mem_working_set_last: 210,
      mem_psi_some10_max: 0, mem_events_high: 2, mem_events_max: 0, mem_oom_kill: 0, mem_refault: 120, runq_count: 340, runq_p99_us: 24000, runq_max_us: 61000 }),
    row({ ts: "2026-09-10T02:41:00", cpu_usage_millis_avg: 100, cpu_usage_millis_max: 150, cpu_nr_periods: 600, cpu_nr_throttled: 0,
      cpu_psi_some10_max: 2, cpu_psi_full10_max: 0, mem_working_set_avg: 100, mem_working_set_max: 120, mem_working_set_last: 110,
      mem_psi_some10_max: 1.5, mem_events_high: 1, mem_events_max: 1, mem_oom_kill: 1, mem_refault: 0, runq_count: 10, runq_p99_us: 900, runq_max_us: 1000 }),
    // a second container, no contention probe (runq null), unlimited CPU (no periods)
    { container_uid: "uid-1/sidecar", container: "sidecar", ts: "2026-09-10T02:41:00", cpu_usage_millis_avg: 5, cpu_usage_millis_max: 9,
      cpu_nr_periods: 0, cpu_nr_throttled: 0, cpu_limit_millis: null, cpu_request_millis: null, runq_count: null, runq_p99_us: null },
  ];
  const out = summariseComputeHistory(rows);
  assert.equal(out.length, 2);
  // sorted by container name
  assert.deepEqual(out.map((c) => c.container), ["api", "sidecar"]);

  const api = out[0];
  assert.equal(api.container_uid, "uid-1/api");
  assert.equal(api.samples, 2);
  assert.deepEqual(api.window, { from: "2026-09-10T02:41:00", to: "2026-09-10T02:42:00" });
  assert.deepEqual(api.cpu_usage_millis, { avg: 200, max: 480, p99: 480 });
  assert.equal(api.cpu_request_millis, 250);
  assert.equal(api.cpu_limit_millis, 500);
  assert.equal(api.cpu_throttled_ratio, 0.25); // 300 / 1200
  assert.equal(api.cpu_psi_some10_max, 31);
  assert.equal(api.cpu_psi_full10_max, 4.2);
  assert.deepEqual(api.mem_working_set_bytes, { avg: 150, max: 220, last: 210 }); // last = newest by ts
  assert.equal(api.mem_limit_bytes, 268435456);
  assert.equal(api.mem_psi_some10_max, 1.5);
  assert.equal(api.mem_events_high, 3);
  assert.equal(api.mem_events_max, 1);
  assert.equal(api.mem_oom_kill, 1);
  assert.equal(api.mem_refault, 120);
  assert.deepEqual(api.runq, { count: 350, p99_us_max: 24000, max_us: 61000 });

  const sidecar = out[1];
  assert.equal(sidecar.cpu_throttled_ratio, null, "no CFS periods ⇒ ratio is null, not 0");
  assert.equal(sidecar.cpu_limit_millis, null);
  assert.equal(sidecar.runq, null, "contention probe not loaded ⇒ runq null");
  assert.deepEqual(sidecar.cpu_usage_millis, { avg: 5, max: 9, p99: 9 });
});

test("summariseComputeHistory tolerates junk input", () => {
  assert.deepEqual(summariseComputeHistory(undefined), []);
  assert.deepEqual(summariseComputeHistory({ rows: [] }), []);
  assert.deepEqual(summariseComputeHistory([null, 42, "x"]), []);
});

test("selectPodFromLatest narrows to the pod's containers and hosting node", () => {
  const latest = {
    containers: [
      { container_uid: "u1/api", pod_uid: "u1", pod_name: "api-1", node: "w3" },
      { container_uid: "u1/side", pod_uid: "u1", pod_name: "api-1", node: "w3" },
      { container_uid: "u2/etl", pod_uid: "u2", pod_name: "etl-1", node: "w4" },
    ],
    nodes: [{ node: "w3", cpu_cores: 8 }, { node: "w4", cpu_cores: 16 }],
  };
  const got = selectPodFromLatest(latest, "api-1");
  assert.ok(got);
  assert.equal(got.pod_uid, "u1");
  assert.equal(got.containers.length, 2);
  assert.deepEqual(got.node, { node: "w3", cpu_cores: 8 });
  assert.equal(selectPodFromLatest(latest, "nope"), null);
  assert.equal(selectPodFromLatest(null, "api-1"), null);
});

// --- executor URL construction ---------------------------------------------
// Every compute tool is exercised against a local broker stand-in that records
// the exact request paths; brokerGetJSON resolves BROKER_URL per call, so
// pointing it here is the repo's established way of mocking the broker.

let server: http.Server;
let requests: string[] = [];
let routes: Record<string, unknown> = {};

before(async () => {
  server = http.createServer((req, res) => {
    requests.push(req.url ?? "");
    const body = routes[(req.url ?? "").split("?")[0]];
    if (body === undefined) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  process.env.BROKER_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => { await new Promise<void>((r) => server.close(() => r())); });

beforeEach(() => { requests = []; routes = {}; });

test("get_compute_findings: no args → bare /compute/findings (cluster scope)", async () => {
  routes = { "/compute/findings": { findings: [] } };
  const got = await executeInProcessTool("get_compute_findings", {});
  assert.equal(got.isError, false, got.text);
  assert.deepEqual(requests, ["/compute/findings"]);
  assert.deepEqual(JSON.parse(got.text), { findings: [] });
});

test("get_compute_findings: namespace + node filters are passed through verbatim", async () => {
  routes = { "/compute/findings": { findings: [{ kind: "noisy-neighbor" }] } };
  const got = await executeInProcessTool("get_compute_findings", { namespace: "payments", node: "worker-3" });
  assert.equal(got.isError, false, got.text);
  assert.deepEqual(requests, ["/compute/findings?namespace=payments&node=worker-3"]);
  assert.deepEqual(JSON.parse(got.text), { findings: [{ kind: "noisy-neighbor" }] });
});

test("get_node_contention: defaults minutes to 5 and honours an explicit value", async () => {
  routes = { "/compute/contention": { pairs: [] } };
  let got = await executeInProcessTool("get_node_contention", { node: "worker-3" });
  assert.equal(got.isError, false, got.text);
  got = await executeInProcessTool("get_node_contention", { node: "worker-3", minutes: 30 });
  assert.equal(got.isError, false, got.text);
  assert.deepEqual(requests, [
    "/compute/contention?node=worker-3&minutes=5",
    "/compute/contention?node=worker-3&minutes=30",
  ]);
});

test("get_node_contention: missing node is a tool error, no broker call", async () => {
  const got = await executeInProcessTool("get_node_contention", {});
  assert.equal(got.isError, true);
  assert.match(got.text, /requires node/);
  assert.deepEqual(requests, []);
});

test("get_pod_compute: latest by namespace, then history by pod_uid for 60 minutes, summarised", async () => {
  routes = {
    "/compute/latest": {
      containers: [
        { container_uid: "u1/api", pod_uid: "u1", pod_name: "api-1", namespace: "payments", container: "api", node: "w3", cpu_usage_millis: 412 },
        { container_uid: "u2/etl", pod_uid: "u2", pod_name: "etl-1", namespace: "payments", container: "worker", node: "w3" },
      ],
      nodes: [{ node: "w3", contention_loaded: true }],
    },
    "/compute/history/u1": {
      rows: [
        { container_uid: "u1/api", container: "api", ts: "t1", cpu_usage_millis_avg: 100, cpu_usage_millis_max: 200, cpu_nr_periods: 100, cpu_nr_throttled: 50 },
        { container_uid: "u1/api", container: "api", ts: "t2", cpu_usage_millis_avg: 300, cpu_usage_millis_max: 400, cpu_nr_periods: 100, cpu_nr_throttled: 0 },
      ],
    },
  };
  const got = await executeInProcessTool("get_pod_compute", { namespace: "payments", pod_name: "api-1" });
  assert.equal(got.isError, false, got.text);
  assert.deepEqual(requests, ["/compute/latest?namespace=payments", "/compute/history/u1?minutes=60"]);
  const out = JSON.parse(got.text);
  assert.equal(out.pod_uid, "u1");
  assert.equal(out.containers.length, 1, "only the requested pod's containers");
  assert.equal(out.containers[0].container_uid, "u1/api");
  assert.deepEqual(out.node, { node: "w3", contention_loaded: true });
  assert.equal(out.history_60m.length, 1);
  assert.deepEqual(out.history_60m[0].cpu_usage_millis, { avg: 200, max: 400, p99: 400 });
  assert.equal(out.history_60m[0].cpu_throttled_ratio, 0.25);
});

test("get_pod_compute: pod with no samples returns an explanatory note and skips history", async () => {
  routes = { "/compute/latest": { containers: [], nodes: [] } };
  const got = await executeInProcessTool("get_pod_compute", { namespace: "payments", pod_name: "ghost" });
  assert.equal(got.isError, false, got.text);
  assert.deepEqual(requests, ["/compute/latest?namespace=payments"]);
  const out = JSON.parse(got.text);
  assert.deepEqual(out.containers, []);
  assert.match(out.note, /no compute samples/);
});

test("get_pod_compute: pod_uid is path-escaped in the history URL", async () => {
  routes = {
    "/compute/latest": { containers: [{ pod_uid: "a/b", pod_name: "p", node: "n" }], nodes: [] },
    "/compute/history/a%2Fb": { rows: [] },
  };
  const got = await executeInProcessTool("get_pod_compute", { namespace: "ns", pod_name: "p" });
  assert.equal(got.isError, false, got.text);
  assert.equal(requests[1], "/compute/history/a%2Fb?minutes=60");
});

test("get_pod_compute: missing namespace or pod_name is a tool error, no broker call", async () => {
  let got = await executeInProcessTool("get_pod_compute", { pod_name: "p" });
  assert.equal(got.isError, true);
  got = await executeInProcessTool("get_pod_compute", { namespace: "ns" });
  assert.equal(got.isError, true);
  assert.deepEqual(requests, []);
});

test("compute tools surface broker errors as is-error results", async () => {
  routes = {}; // everything 404s
  const got = await executeInProcessTool("get_compute_findings", { namespace: "x" });
  assert.equal(got.isError, true);
  assert.match(got.text, /broker returned 404/);
});
