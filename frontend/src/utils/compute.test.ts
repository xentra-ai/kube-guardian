import { describe, expect, test } from 'vitest';
import {
  COMPUTE_STATE_OFF,
  COMPUTE_STATE_PENDING,
  COMPUTE_STATE_UNSUPPORTED,
  NODE_HEIGHT_BASE,
  NODE_HEIGHT_EXPANDED,
  NODE_HEIGHT_GAUGE_ROW,
  NODE_HEIGHT_SPARKLINES,
  RingBuffer,
  buildPodComputeData,
  containersForNode,
  formatBytes,
  formatMicros,
  formatMillicores,
  hasComputeGauges,
  nodeComputeState,
  nodeHeight,
  pickDenominator,
  podLevelSample,
  statusFromFindings,
  statusTooltip,
  throttledRatio,
} from './compute';
import type { ComputeContainer, ComputeFinding, ComputeNode } from '../types/compute';
import type { PodInfo } from '../types';

const container = (over: Partial<ComputeContainer> = {}): ComputeContainer => ({
  container_uid: 'uid-a/app', pod_uid: 'uid-a', namespace: 'payments', pod_name: 'api-1', container: 'app', node: 'worker-1',
  cgroup_id: 1, ts: 't', interval_ms: 5000,
  cpu_usage_millis: 100, cpu_quota_usec: null, cpu_period_usec: 100000, cpu_request_millis: 250, cpu_limit_millis: 500,
  cpu_nr_periods: 50, cpu_nr_throttled: 0, cpu_throttled_usec: 0, cpu_psi_some10: 0, cpu_psi_full10: 0,
  mem_current: 1000, mem_working_set: 800, mem_limit: 4000, mem_request: 2000, mem_psi_some10: 0, mem_psi_full10: 0,
  mem_events_high: 0, mem_events_max: 0, mem_oom_kill: 0, mem_refault: 0, mem_pgmajfault: 0,
  runq_count: null, runq_p50_us: null, runq_p95_us: null, runq_p99_us: null, runq_max_us: null, runq_overflow: null,
  blame: null, updated_at: 't',
  ...over,
});
const node = (over: Partial<ComputeNode> = {}): ComputeNode => ({
  node: 'worker-1', ts: 't', interval_ms: 5000, ctxt_per_sec: 0,
  compute_enabled: true, compute_supported: true, contention_loaded: false,
  cpu_some10: 0, cpu_full10: 0, mem_some10: 0, mem_full10: 0, cpu_cores: 4, memory_bytes: 8000,
  bpf_runq_enqueued: 0, bpf_runq_hist: 0, bpf_pair: 0, unknown_blame_share: 0, updated_at: 't', ...over,
});
const finding = (severity: ComputeFinding['severity'], kind: ComputeFinding['kind'] = 'cpu-throttled'): ComputeFinding => ({
  kind, severity,
  victim: { pod_uid: 'uid-a', namespace: 'payments', pod_name: 'api-1', container: 'app', container_uid: 'uid-a/app', node: 'worker-1' },
  culprit: null,
  evidence: { window_minutes: 5, cpu_psi_some10_max: 0, cpu_psi_full10_max: 0, runq_p99_us_max: null, throttled_ratio: 0.3, mem_psi_some10_max: 0, node_mem_some10_max: 0, refault_delta: 0, mem_events_high_delta: 0 },
  first_seen: 't', last_seen: 't', message: 'm',
});

describe('nodeHeight (design D8: a function of expansion AND compute presence)', () => {
  test('collapsed, no compute = the pre-feature height', () => {
    expect(nodeHeight({ isExpanded: false, hasCompute: false })).toBe(100);
    expect(NODE_HEIGHT_BASE).toBe(100);
  });
  test('each state adds its rows, in a strict order', () => {
    const c = nodeHeight({ isExpanded: false, hasCompute: false });
    const cg = nodeHeight({ isExpanded: false, hasCompute: true });
    const e = nodeHeight({ isExpanded: true, hasCompute: false });
    const eg = nodeHeight({ isExpanded: true, hasCompute: true });
    expect(cg).toBe(c + NODE_HEIGHT_GAUGE_ROW);
    expect(e).toBe(c + NODE_HEIGHT_EXPANDED);
    expect(eg).toBe(c + NODE_HEIGHT_GAUGE_ROW + NODE_HEIGHT_EXPANDED + NODE_HEIGHT_SPARKLINES);
    expect(c).toBeLessThan(cg);
    expect(cg).toBeLessThan(e);
    expect(e).toBeLessThan(eg);
  });
});

describe('RingBuffer', () => {
  test('keeps the last N, oldest first', () => {
    const b = new RingBuffer<number>(3);
    [1, 2, 3, 4, 5].forEach((n) => b.push(n));
    expect(b.values()).toEqual([3, 4, 5]);
    expect(b.length).toBe(3);
    expect(b.last()).toBe(5);
  });
  test('values() is a copy', () => {
    const b = new RingBuffer<number>(3);
    b.push(1);
    const v = b.values();
    v.push(99);
    expect(b.values()).toEqual([1]);
  });
});

describe('podLevelSample', () => {
  test('sums the containers cpu millis and working set', () => {
    const s = podLevelSample([container({ cpu_usage_millis: 100, mem_working_set: 10 }), container({ cpu_usage_millis: 50, mem_working_set: 5 })], 123);
    expect(s).toEqual({ at: 123, cpuMillis: 150, workingSetBytes: 15 });
  });
});

describe('pickDenominator (limit → request → node)', () => {
  test('limit when every container has one', () => {
    expect(pickDenominator([500, 200], [100, 100], 4000)).toEqual({ value: 700, kind: 'limit' });
  });
  test('request when a container has no limit', () => {
    expect(pickDenominator([500, null], [100, 100], 4000)).toEqual({ value: 200, kind: 'request' });
  });
  test('node capacity when neither is complete', () => {
    expect(pickDenominator([null], [null], 4000)).toEqual({ value: 4000, kind: 'node' });
  });
  test('null when nothing is known', () => {
    expect(pickDenominator([null], [null], null)).toBeNull();
    expect(pickDenominator([], [], null)).toBeNull();
  });
});

describe('statusFromFindings / nodeComputeState / statusTooltip', () => {
  test('worst severity wins: critical → critical, high/medium → warning, none → ok', () => {
    expect(statusFromFindings([])).toBe('ok');
    expect(statusFromFindings([finding('medium')])).toBe('warning');
    expect(statusFromFindings([finding('medium'), finding('high')])).toBe('warning');
    expect(statusFromFindings([finding('high'), finding('critical')])).toBe('critical');
  });
  test('node row gates: no row → pending, off → off, unsupported → unsupported', () => {
    // Fix #4: an absent node row is "not reported (yet)", never "feature off".
    expect(nodeComputeState(undefined)).toBe('pending');
    expect(nodeComputeState(node({ compute_enabled: false }))).toBe('off');
    expect(nodeComputeState(node({ compute_supported: false }))).toBe('unsupported');
    expect(nodeComputeState(node())).toBe('ok');
  });
  test('unsupported, off and pending explain themselves differently', () => {
    expect(statusTooltip('unsupported')).toMatch(/cgroup v1/);
    expect(statusTooltip('off')).toMatch(/compute\.enabled/);
    expect(statusTooltip('pending')).toMatch(/not yet sampled, or opted out with kguardian\.dev\/compute: off/);
    expect(new Set([statusTooltip('unsupported'), statusTooltip('off'), statusTooltip('pending')]).size).toBe(3);
    expect(statusTooltip('critical', [finding('critical', 'noisy-neighbor')])).toBe('Compute critical: noisy-neighbor');
  });
});

describe('buildPodComputeData', () => {
  test('no rows on a reporting node → the shared PENDING constant (fix #4)', () => {
    const d = buildPodComputeData({ containers: [], nodesByName: new Map([['worker-1', node()]]), findings: [], samples: [], nodeState: 'ok' });
    expect(d).toBe(COMPUTE_STATE_PENDING);
    expect(d.status).toBe('pending');
    expect(hasComputeGauges(d)).toBe(false);
  });
  test('no rows, node unknown → pending, never off', () => {
    expect(buildPodComputeData({ containers: [], nodesByName: new Map(), findings: [], samples: [] })).toBe(COMPUTE_STATE_PENDING);
  });
  test('no rows on an off / unsupported node → the shared constants, same identity every tick (fix #8)', () => {
    const off1 = buildPodComputeData({ containers: [], nodesByName: new Map(), findings: [], samples: [], nodeState: 'off' });
    const off2 = buildPodComputeData({ containers: [], nodesByName: new Map(), findings: [], samples: [], nodeState: 'off' });
    expect(off1).toBe(COMPUTE_STATE_OFF);
    expect(off1).toBe(off2);
    expect(Object.isFrozen(off1)).toBe(true);
    const u = buildPodComputeData({ containers: [], nodesByName: new Map(), findings: [], samples: [], nodeState: 'unsupported' });
    expect(u).toBe(COMPUTE_STATE_UNSUPPORTED);
    expect(u.status).toBe('unsupported');
    expect(hasComputeGauges(u)).toBe(false);
    expect(u.cpuPct).toBeNull();
  });
  test('percentages against the picked denominator, sparklines from the samples', () => {
    const rows = [container({ cpu_limit_millis: 500, mem_limit: null, mem_request: 2000 })];
    const samples = [
      { at: 1, cpuMillis: 100, workingSetBytes: 500 },
      { at: 2, cpuMillis: 250, workingSetBytes: 1000 },
    ];
    const d = buildPodComputeData({ containers: rows, nodesByName: new Map([['worker-1', node()]]), findings: [finding('high')], samples })!;
    expect(d.cpuPct).toBe(50);
    expect(d.cpuDenominator).toBe('limit');
    expect(d.memPct).toBe(50);
    expect(d.memDenominator).toBe('request');
    expect(d.sparkCpu).toEqual([100, 250]);
    expect(d.sparkMem).toEqual([500, 1000]);
    expect(d.status).toBe('warning');
    expect(hasComputeGauges(d)).toBe(true);
  });
  test('falls back to node capacity (cores × 1000) when nothing is set', () => {
    const rows = [container({ cpu_limit_millis: null, cpu_request_millis: null, mem_limit: null, mem_request: null, cpu_usage_millis: 400, mem_working_set: 4000 })];
    const d = buildPodComputeData({ containers: rows, nodesByName: new Map([['worker-1', node()]]), findings: [], samples: [] })!;
    expect(d.cpuDenominator).toBe('node');
    expect(d.cpuCapacityMillis).toBe(4000);
    expect(d.cpuPct).toBe(10);
    expect(d.memDenominator).toBe('node');
    expect(d.memPct).toBe(50);
  });
  test('dropped BPF inserts on the node: probeDrops set, status at least warning, tooltip appended', () => {
    const nodes = new Map([['worker-1', node({ bpf_hist_update_failures: 3, bpf_pair_update_failures: 5 })]]);
    const d = buildPodComputeData({ containers: [container()], nodesByName: nodes, findings: [], samples: [] });
    expect(d.probeDrops).toEqual({ hist: 3, pair: 5 });
    expect(d.status).toBe('warning');
    expect(statusTooltip(d.status, d.findings, d.probeDrops)).toBe('Compute warning; probe map full: 3 histogram / 5 pair inserts dropped');
    // A critical finding is not downgraded; zero / absent counters mean no drops.
    const c = buildPodComputeData({ containers: [container()], nodesByName: nodes, findings: [finding('critical')], samples: [] });
    expect(c.status).toBe('critical');
    const clean = buildPodComputeData({ containers: [container()], nodesByName: new Map([['worker-1', node({ bpf_hist_update_failures: 0, bpf_pair_update_failures: null })]]), findings: [], samples: [] });
    expect(clean.probeDrops).toBeNull();
    expect(clean.status).toBe('ok');
    expect(buildPodComputeData({ containers: [container()], nodesByName: new Map([['worker-1', node()]]), findings: [], samples: [] }).probeDrops).toBeNull();
  });
  test('an off node overrides findings on the dot; rows on an unknown node are ok, not pending', () => {
    const d = buildPodComputeData({ containers: [container()], nodesByName: new Map(), findings: [finding('critical')], samples: [], nodeState: 'off' });
    expect(d.status).toBe('off');
    const p = buildPodComputeData({ containers: [container()], nodesByName: new Map(), findings: [], samples: [] });
    expect(p.status).toBe('ok');
  });
});

describe('containersForNode', () => {
  const pod = (name: string, uid?: string): PodInfo => ({
    pod_name: name, pod_ip: '', pod_namespace: 'payments', time_stamp: 't', node_name: 'n', is_dead: false,
    pod_obj: uid ? { metadata: { uid } } : undefined,
  });
  test('matches by uid when the record carries one, else by ns/name; de-duplicates', () => {
    const rowA = container({ container_uid: 'uid-a/app', pod_uid: 'uid-a', pod_name: 'api-1' });
    const rowB = container({ container_uid: 'uid-b/app', pod_uid: 'uid-b', pod_name: 'api-2' });
    const byUid = new Map([['uid-a', [rowA]]]);
    const byName = new Map([['payments/api-1', [rowA]], ['payments/api-2', [rowB]]]);
    const out = containersForNode({ pod: pod('api-1', 'uid-a'), pods: [pod('api-1', 'uid-a'), pod('api-2')] }, byUid, byName);
    expect(out.map((c) => c.container_uid)).toEqual(['uid-a/app', 'uid-b/app']);
  });
});

describe('formatting', () => {
  test('millicores, bytes, micros, throttle ratio', () => {
    expect(formatMillicores(250)).toBe('250m');
    expect(formatMillicores(1900)).toBe('1.90 cores');
    expect(formatMillicores(null)).toBe('—');
    expect(formatBytes(171000000)).toBe('163 MiB');
    expect(formatBytes(1300 * 1024 * 1024)).toBe('1.3 GiB');
    expect(formatMicros(24000)).toBe('24.0 ms');
    expect(formatMicros(90)).toBe('90 µs');
    expect(throttledRatio(container({ cpu_throttled_usec: 1_250_000, cpu_nr_periods: 50, cpu_period_usec: 100_000 }))).toBe(0.25);
    expect(throttledRatio(container({ cpu_nr_periods: 0 }))).toBeNull();
  });
});
