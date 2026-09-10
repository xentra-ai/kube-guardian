// Pure helpers behind the live compute gauges (design D8). Everything the
// PodNode, DataTable and Findings surfaces derive from `pod_compute_latest`
// rows lives here so it can be tested without React Flow.

import type { PodInfo, PodNodeData } from '../types';
import type {
  ComputeContainer,
  ComputeDenominator,
  ComputeFinding,
  ComputeFindingKind,
  ComputeNode,
  ComputeSample,
  ComputeSeverity,
  ComputeStatus,
  PodComputeData,
} from '../types/compute';
import { podUid } from './peerResolution';

/** Client-side history depth per pod (D8: "last 60 samples kept client-side"). */
export const COMPUTE_HISTORY_SAMPLES = 60;

/** Fixed-capacity FIFO of the last N samples, oldest first. */
export class RingBuffer<T> {
  private items: T[] = [];
  readonly capacity: number;
  constructor(capacity: number = COMPUTE_HISTORY_SAMPLES) {
    this.capacity = capacity;
  }

  push(item: T): void {
    this.items.push(item);
    if (this.items.length > this.capacity) this.items.splice(0, this.items.length - this.capacity);
  }

  /** Oldest → newest snapshot (a copy; safe to hand to React). */
  values(): T[] {
    return [...this.items];
  }

  get length(): number {
    return this.items.length;
  }

  last(): T | undefined {
    return this.items[this.items.length - 1];
  }
}

/** A pod's compute is the sum of its containers' CPU millis / working set. */
export function podLevelSample(containers: readonly ComputeContainer[], at: number): ComputeSample {
  let cpuMillis = 0;
  let workingSetBytes = 0;
  for (const c of containers) {
    cpuMillis += Number.isFinite(c.cpu_usage_millis) ? c.cpu_usage_millis : 0;
    workingSetBytes += Number.isFinite(c.mem_working_set) ? c.mem_working_set : 0;
  }
  return { at, cpuMillis, workingSetBytes };
}

/**
 * The capacity a gauge is normalised against, in D8 priority order: the
 * pod's summed limits when EVERY container has one, else its summed
 * requests when every container has one, else the node's capacity. Mixed
 * pods (one container limited, one not) fall through — a partial sum would
 * read as a bound the pod does not actually have.
 */
export function pickDenominator(
  perContainer: readonly (number | null | undefined)[],
  requests: readonly (number | null | undefined)[],
  nodeCapacity: number | null | undefined,
): { value: number; kind: ComputeDenominator } | null {
  const sumIfAll = (xs: readonly (number | null | undefined)[]): number | null => {
    if (xs.length === 0) return null;
    let total = 0;
    for (const x of xs) {
      if (x === null || x === undefined || !(x > 0)) return null;
      total += x;
    }
    return total;
  };
  const limit = sumIfAll(perContainer);
  if (limit !== null) return { value: limit, kind: 'limit' };
  const request = sumIfAll(requests);
  if (request !== null) return { value: request, kind: 'request' };
  if (nodeCapacity !== null && nodeCapacity !== undefined && nodeCapacity > 0) return { value: nodeCapacity, kind: 'node' };
  return null;
}

/** Percentage (0..∞, callers clamp for drawing) or null without a denominator. */
export function percentOf(value: number, denominator: { value: number } | null): number | null {
  if (!denominator || denominator.value <= 0) return null;
  return (value / denominator.value) * 100;
}

const SEVERITY_RANK: Record<ComputeSeverity, number> = { critical: 3, high: 2, medium: 1 };

/** The worst finding's severity → dot state; no findings → ok. */
export function statusFromFindings(findings: readonly ComputeFinding[]): Extract<ComputeStatus, 'ok' | 'warning' | 'critical'> {
  let worst: ComputeSeverity | null = null;
  for (const f of findings) {
    if (worst === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity;
  }
  if (worst === 'critical') return 'critical';
  if (worst === 'high' || worst === 'medium') return 'warning';
  return 'ok';
}

export type NodeComputeState = 'ok' | 'unsupported' | 'off' | 'pending';

/**
 * Node-level gate (D10): a node row with `compute_enabled=false` renders its
 * pods as `off`; `compute_supported=false` (cgroup v1 / no PSI) as
 * `unsupported`. No node row at all is `pending` — the node has not
 * reported (yet); it is NOT evidence the feature is off.
 */
export function nodeComputeState(node: ComputeNode | undefined): NodeComputeState {
  if (!node) return 'pending';
  if (!node.compute_enabled) return 'off';
  if (!node.compute_supported) return 'unsupported';
  return 'ok';
}

/** Tooltip copy for the header dot, so `unsupported` and `off` read apart. */
export function statusTooltip(status: ComputeStatus, findings: readonly ComputeFinding[] = []): string {
  switch (status) {
    case 'off':
      return 'Compute gauges off: compute.enabled is false on this node, or the controller predates the feature';
    case 'unsupported':
      return 'Compute gauges unsupported on this node (cgroup v1 or no PSI)';
    case 'pending':
      return 'No compute sample yet for this pod';
    case 'ok':
      return 'Compute: no active findings';
    default: {
      const kinds = [...new Set(findings.map((f) => f.kind))].join(', ');
      return `Compute ${status}: ${kinds || 'active findings'}`;
    }
  }
}

/** The pod uid a compute row keys on, when the stored manifest carries it. */
export function podKeysFor(pod: PodInfo): { uid: string | undefined; name: string; namespace: string | null } {
  return { uid: podUid(pod), name: pod.pod_name, namespace: pod.pod_namespace };
}

/**
 * Compute rows for a graph node: matched by pod uid when the pod record
 * carries one, else by `namespace/pod_name` — a compute row always carries
 * both, a PodInfo only sometimes carries the uid.
 */
export function containersForNode(
  node: Pick<PodNodeData, 'pod' | 'pods'>,
  containersByPodUid: ReadonlyMap<string, ComputeContainer[]>,
  containersByPodName: ReadonlyMap<string, ComputeContainer[]>,
): ComputeContainer[] {
  const members = node.pods && node.pods.length > 0 ? node.pods : [node.pod];
  const out: ComputeContainer[] = [];
  const seen = new Set<string>();
  for (const m of members) {
    const { uid, name, namespace } = podKeysFor(m);
    const rows = (uid && containersByPodUid.get(uid)) || containersByPodName.get(`${namespace ?? ''}/${name}`) || [];
    for (const r of rows) {
      if (!seen.has(r.container_uid)) {
        seen.add(r.container_uid);
        out.push(r);
      }
    }
  }
  return out;
}

/** `<ns>/<pod_name>` — the fallback join key for rows and pods. */
export const podNameKey = (namespace: string | null | undefined, name: string): string => `${namespace ?? ''}/${name}`;

export interface BuildPodComputeInput {
  containers: readonly ComputeContainer[];
  nodesByName: ReadonlyMap<string, ComputeNode>;
  /** Findings whose victim is one of this pod's containers. */
  findings: readonly ComputeFinding[];
  /** Oldest-first client-side samples for this pod. */
  samples: readonly ComputeSample[];
  /** Whether the pod's node reported compute at all (see nodeComputeState). */
  nodeState?: NodeComputeState;
}

const frozenArray = <T,>(): T[] => Object.freeze([]) as unknown as T[];
const emptyState = (status: ComputeStatus): PodComputeData =>
  Object.freeze({
    cpuPct: null, memPct: null, cpuDenominator: null, memDenominator: null,
    status, findings: frozenArray<ComputeFinding>(), sparkCpu: frozenArray<number>(), sparkMem: frozenArray<number>(),
    cpuMillis: null, memBytes: null, cpuCapacityMillis: null, memCapacityBytes: null,
    containers: frozenArray<ComputeContainer>(),
  });

// Shared, frozen "no rows" states. Returned by identity so a pod without
// rows keeps the same `compute` object across polls and PodNode's memo
// (which compares by identity) does not repaint it every 5 s.
export const COMPUTE_STATE_OFF: PodComputeData = emptyState('off');
export const COMPUTE_STATE_UNSUPPORTED: PodComputeData = emptyState('unsupported');
export const COMPUTE_STATE_PENDING: PodComputeData = emptyState('pending');

/**
 * Everything PodNode needs, from a pod's rows. Without rows the result is
 * one of the shared constants above: `off` / `unsupported` only when the
 * node row says so, `pending` when the node has not reported or the pod has
 * no sample yet. Callers leave `compute` undefined entirely when the feature
 * is off cluster-wide (hook `enabled=false`).
 */
export function buildPodComputeData(input: BuildPodComputeInput): PodComputeData {
  const { containers, nodesByName, findings, samples } = input;
  const nodeName = containers[0]?.node;
  const nodeRow = nodeName ? nodesByName.get(nodeName) : undefined;
  const nodeState = input.nodeState ?? nodeComputeState(nodeRow);

  if (containers.length === 0) {
    if (nodeState === 'off') return COMPUTE_STATE_OFF;
    if (nodeState === 'unsupported') return COMPUTE_STATE_UNSUPPORTED;
    return COMPUTE_STATE_PENDING;
  }

  const latest = samples[samples.length - 1] ?? podLevelSample(containers, Date.now());
  const cpuDen = pickDenominator(
    containers.map((c) => c.cpu_limit_millis),
    containers.map((c) => c.cpu_request_millis),
    nodeRow?.cpu_cores != null ? nodeRow.cpu_cores * 1000 : null,
  );
  const memDen = pickDenominator(
    containers.map((c) => c.mem_limit),
    containers.map((c) => c.mem_request),
    nodeRow?.memory_bytes ?? null,
  );

  // Rows exist, so the node is reporting: `pending` cannot apply here.
  const status: ComputeStatus = nodeState === 'off' || nodeState === 'unsupported' ? nodeState : statusFromFindings(findings);

  return {
    cpuPct: percentOf(latest.cpuMillis, cpuDen),
    memPct: percentOf(latest.workingSetBytes, memDen),
    cpuDenominator: cpuDen?.kind ?? null,
    memDenominator: memDen?.kind ?? null,
    status,
    findings: [...findings],
    sparkCpu: samples.map((s) => s.cpuMillis),
    sparkMem: samples.map((s) => s.workingSetBytes),
    cpuMillis: latest.cpuMillis,
    memBytes: latest.workingSetBytes,
    cpuCapacityMillis: cpuDen?.value ?? null,
    memCapacityBytes: memDen?.value ?? null,
    containers: [...containers],
  };
}

/** Throttled share of the sample's CFS periods (D3), 0..1, or null without periods. */
export function throttledRatio(c: Pick<ComputeContainer, 'cpu_throttled_usec' | 'cpu_nr_periods' | 'cpu_period_usec'>): number | null {
  const denom = c.cpu_nr_periods * c.cpu_period_usec;
  if (!(denom > 0)) return null;
  return Math.min(1, c.cpu_throttled_usec / denom);
}

/** The `noisy-neighbor` finding naming a pod culprit, if any (the "Starved by" chip). */
export function starvedBy(findings: readonly ComputeFinding[]): ComputeFinding | undefined {
  return findings.find((f) => f.kind === 'noisy-neighbor' && f.culprit !== null);
}

/** The `cpu-throttled` finding, if any (the "Throttled NN%" chip). */
export function throttledFinding(findings: readonly ComputeFinding[]): ComputeFinding | undefined {
  return findings.find((f) => f.kind === 'cpu-throttled');
}

// Header status dot per compute state (design D8). ok/warning/critical take
// the semantic tokens; unsupported/off take a muted token so "no gauge" never
// reads as "healthy" — the tooltip says which of the two it is.
export const COMPUTE_DOT_CLASS: Record<ComputeStatus, string> = {
  ok: 'bg-hubble-success',
  warning: 'bg-hubble-warning',
  critical: 'bg-hubble-error',
  unsupported: 'bg-hubble-border-strong',
  off: 'bg-hubble-border',
  pending: 'bg-hubble-border animate-pulse',
};

/**
 * What a culprit's `blame_share` is a share OF — it differs by kind (see the
 * type comment on `ComputeFindingCulprit.blame_share`).
 */
export function blameShareLabel(kind: ComputeFindingKind, share: number): string {
  const pct = `${Math.round(share * 100)}%`;
  return kind === 'memory-pressure' ? `${pct} of node memory overage` : `${pct} of its CPU wait`;
}

/** Culprit usage for labels; an opted-out culprit has none. */
export const CULPRIT_USAGE_UNKNOWN = 'usage unknown (opted out of sampling)';
export function culpritUsageLabel(usageMillis: number | null): string {
  return usageMillis === null ? CULPRIT_USAGE_UNKNOWN : `using ${formatMillicores(usageMillis)}`;
}

export const COMPUTE_KIND_LABEL: Record<ComputeFindingKind, string> = {
  'noisy-neighbor': 'Noisy neighbour',
  'cpu-throttled': 'CPU throttled',
  'cpu-contended': 'CPU contended',
  'memory-pressure': 'Memory pressure',
  'memory-limit-thrash': 'Memory limit thrash',
};

// ── Formatting ──

export function formatMillicores(millis: number | null | undefined): string {
  if (millis === null || millis === undefined || !Number.isFinite(millis)) return '—';
  if (millis >= 1000) return `${(millis / 1000).toFixed(millis >= 10_000 ? 0 : 2)} cores`;
  return `${Math.round(millis)}m`;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export function formatPercent(pct: number | null | undefined, digits = 0): string {
  if (pct === null || pct === undefined || !Number.isFinite(pct)) return '—';
  return `${pct.toFixed(digits)}%`;
}

export function formatMicros(us: number | null | undefined): string {
  if (us === null || us === undefined || !Number.isFinite(us)) return '—';
  if (us >= 1_000_000) return `${(us / 1_000_000).toFixed(2)} s`;
  if (us >= 1000) return `${(us / 1000).toFixed(us >= 100_000 ? 0 : 1)} ms`;
  return `${Math.round(us)} µs`;
}

/** Denominator wording for tooltips: "of 500m limit". */
export function denominatorLabel(kind: ComputeDenominator | null): string {
  switch (kind) {
    case 'limit': return 'limit';
    case 'request': return 'request';
    case 'node': return 'node capacity';
    default: return 'no capacity known';
  }
}

// ── Graph layout ──

/** Collapsed card, no gauges (the pre-feature `NODE_HEIGHT`). */
export const NODE_HEIGHT_BASE = 100;
/** The micro bar row under the title. */
export const NODE_HEIGHT_GAUGE_ROW = 14;
/** Expanded body (stat chips + Build Policy). */
export const NODE_HEIGHT_EXPANDED = 90;
/** Two sparklines + labels + chips in the expanded body. */
export const NODE_HEIGHT_SPARKLINES = 120;

/**
 * Estimated card height for ELK (D8): the base collapsed card, plus the
 * gauge row when the pod has compute data, plus the expanded body, plus the
 * sparklines when both expanded and gauged. Used at BOTH ELK call sites.
 */
export function nodeHeight(opts: { isExpanded: boolean; hasCompute: boolean }): number {
  let h = NODE_HEIGHT_BASE;
  if (opts.hasCompute) h += NODE_HEIGHT_GAUGE_ROW;
  if (opts.isExpanded) h += NODE_HEIGHT_EXPANDED;
  if (opts.isExpanded && opts.hasCompute) h += NODE_HEIGHT_SPARKLINES;
  return h;
}

/** Whether a node shows gauges (its status dot is not `off` / `unsupported` with no data). */
export function hasComputeGauges(compute: PodComputeData | undefined): boolean {
  return !!compute && compute.containers.length > 0;
}
