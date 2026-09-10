// Compute-contention tool support: broker query construction and the
// 60-minute history summariser behind get_pod_compute. Pure functions —
// the executor (execute.ts) does the fetching. Wire shapes follow
// docs/design/compute-contention-monitoring.md and the shared
// compute-contract: rows are pod_compute_latest / pod_compute_history rows
// as the broker serialises them (snake_case), and this module only reads
// the fields it summarises, so extra columns pass through untouched.

/** Build the query string for the /compute/* broker endpoints. Omits empty
 *  or non-positive values so callers can pass optional args straight through. */
export function computeQuery(args: { namespace?: string; node?: string; minutes?: number }): string {
  const q = new URLSearchParams();
  if (args.namespace) q.set("namespace", args.namespace);
  if (args.node) q.set("node", args.node);
  if (typeof args.minutes === "number" && Number.isFinite(args.minutes) && args.minutes > 0) {
    q.set("minutes", String(Math.floor(args.minutes)));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

/** The subset of a pod_compute_history row the summariser reads. */
export interface ComputeHistoryRow {
  container_uid?: string;
  container?: string;
  ts?: string;
  cpu_usage_millis_avg?: number | null;
  cpu_usage_millis_max?: number | null;
  cpu_limit_millis?: number | null;
  cpu_request_millis?: number | null;
  cpu_nr_periods?: number | null;
  cpu_nr_throttled?: number | null;
  cpu_throttled_usec?: number | null;
  cpu_period_usec?: number | null;
  cpu_psi_some10_max?: number | null;
  cpu_psi_full10_max?: number | null;
  mem_working_set_avg?: number | null;
  mem_working_set_max?: number | null;
  mem_working_set_last?: number | null;
  mem_limit?: number | null;
  mem_request?: number | null;
  mem_psi_some10_max?: number | null;
  mem_events_high?: number | null;
  mem_events_max?: number | null;
  mem_oom_kill?: number | null;
  mem_refault?: number | null;
  runq_count?: number | null;
  runq_p99_us?: number | null;
  runq_max_us?: number | null;
  [k: string]: unknown;
}

export interface ContainerComputeSummary {
  container_uid: string;
  container: string;
  samples: number;
  window: { from: string | null; to: string | null };
  cpu_usage_millis: { avg: number | null; max: number | null; p99: number | null };
  cpu_request_millis: number | null;
  cpu_limit_millis: number | null;
  /** Broker / design D3 definition: Σ throttled_usec ÷ Σ (nr_periods × period_usec) over the
   *  window — the share of quota-time lost to throttling. null when unlimited (no CFS
   *  periods) or when the period is unknown. */
  cpu_throttled_ratio: number | null;
  cpu_psi_some10_max: number | null;
  cpu_psi_full10_max: number | null;
  mem_working_set_bytes: { avg: number | null; max: number | null; last: number | null };
  mem_request_bytes: number | null;
  mem_limit_bytes: number | null;
  mem_psi_some10_max: number | null;
  mem_events_high: number;
  mem_events_max: number;
  mem_oom_kill: number;
  mem_refault: number;
  /** Scheduler run-queue latency from the contention probe; null when it was not loaded. */
  runq: { count: number; p99_us_max: number | null; max_us: number | null } | null;
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

function mean(xs: number[]): number | null {
  if (xs.length === 0) return null;
  return round(xs.reduce((a, b) => a + b, 0) / xs.length);
}

function max(xs: number[]): number | null {
  return xs.length === 0 ? null : Math.max(...xs);
}

function sum(xs: number[]): number {
  return xs.reduce((a, b) => a + b, 0);
}

/** Nearest-rank p99 over the per-minute maxima. With fewer than 100 samples
 *  this is the maximum, which is the honest answer for a short window. */
export function p99(xs: number[]): number | null {
  if (xs.length === 0) return null;
  const sorted = [...xs].sort((a, b) => a - b);
  const rank = Math.ceil(0.99 * sorted.length); // 1-based nearest rank
  return sorted[Math.min(sorted.length, Math.max(1, rank)) - 1];
}

function round(x: number): number {
  return Math.round(x * 1000) / 1000;
}

/** Summarise history rows (any resolution, any order) into one entry per
 *  container. Counters are summed, gauges are avg-of-avg / max-of-max, and
 *  the last working-set value is taken from the newest row by ts. */
export function summariseComputeHistory(rows: unknown): ContainerComputeSummary[] {
  if (!Array.isArray(rows)) return [];
  const byContainer = new Map<string, ComputeHistoryRow[]>();
  for (const r of rows as ComputeHistoryRow[]) {
    if (!r || typeof r !== "object") continue;
    const key = typeof r.container_uid === "string" && r.container_uid ? r.container_uid : String(r.container ?? "");
    const list = byContainer.get(key);
    if (list) list.push(r);
    else byContainer.set(key, [r]);
  }

  const out: ContainerComputeSummary[] = [];
  for (const [uid, list] of byContainer) {
    const sorted = [...list].sort((a, b) => String(a.ts ?? "").localeCompare(String(b.ts ?? "")));
    const newest = sorted[sorted.length - 1];
    const pick = (f: (r: ComputeHistoryRow) => unknown): number[] =>
      sorted.map(f).map(num).filter((v): v is number => v !== null);

    // Denominator is accumulated per row so a mid-window period change
    // (limit edited in place) is weighted correctly rather than assuming
    // one period for the whole window.
    let quotaTimeUsec = 0;
    let throttledUsec = 0;
    for (const r of sorted) {
      const periods = num(r.cpu_nr_periods);
      const period = num(r.cpu_period_usec);
      if (periods === null || periods <= 0 || period === null || period <= 0) continue;
      quotaTimeUsec += periods * period;
      throttledUsec += num(r.cpu_throttled_usec) ?? 0;
    }
    const runqP99s = pick((r) => r.runq_p99_us);
    const runqLoaded = runqP99s.length > 0 || pick((r) => r.runq_count).length > 0;

    out.push({
      container_uid: uid,
      container: String(newest.container ?? uid.split("/").pop() ?? ""),
      samples: sorted.length,
      window: { from: sorted[0].ts ?? null, to: newest.ts ?? null },
      cpu_usage_millis: {
        avg: mean(pick((r) => r.cpu_usage_millis_avg)),
        max: max(pick((r) => r.cpu_usage_millis_max)),
        p99: p99(pick((r) => r.cpu_usage_millis_max)),
      },
      cpu_request_millis: num(newest.cpu_request_millis),
      cpu_limit_millis: num(newest.cpu_limit_millis),
      cpu_throttled_ratio: quotaTimeUsec > 0 ? round(throttledUsec / quotaTimeUsec) : null,
      cpu_psi_some10_max: max(pick((r) => r.cpu_psi_some10_max)),
      cpu_psi_full10_max: max(pick((r) => r.cpu_psi_full10_max)),
      mem_working_set_bytes: {
        avg: mean(pick((r) => r.mem_working_set_avg)),
        max: max(pick((r) => r.mem_working_set_max)),
        last: num(newest.mem_working_set_last),
      },
      mem_request_bytes: num(newest.mem_request),
      mem_limit_bytes: num(newest.mem_limit),
      mem_psi_some10_max: max(pick((r) => r.mem_psi_some10_max)),
      mem_events_high: sum(pick((r) => r.mem_events_high)),
      mem_events_max: sum(pick((r) => r.mem_events_max)),
      mem_oom_kill: sum(pick((r) => r.mem_oom_kill)),
      mem_refault: sum(pick((r) => r.mem_refault)),
      runq: runqLoaded
        ? { count: sum(pick((r) => r.runq_count)), p99_us_max: max(runqP99s), max_us: max(pick((r) => r.runq_max_us)) }
        : null,
    });
  }
  return out.sort((a, b) => a.container.localeCompare(b.container));
}

/** Minimal shape of GET /compute/latest. */
export interface ComputeLatestResponse {
  containers?: Array<{ pod_uid?: string; pod_name?: string; node?: string; [k: string]: unknown }>;
  nodes?: Array<{ node?: string; [k: string]: unknown }>;
}

/** Narrow a /compute/latest response to a single pod: its container rows and
 *  the node row hosting it. Returns null when the pod has no samples. */
export function selectPodFromLatest(latest: unknown, podName: string): {
  pod_uid: string | null;
  containers: NonNullable<ComputeLatestResponse["containers"]>;
  node: Record<string, unknown> | null;
} | null {
  const l = (latest ?? {}) as ComputeLatestResponse;
  const containers = (Array.isArray(l.containers) ? l.containers : []).filter((c) => c && c.pod_name === podName);
  if (containers.length === 0) return null;
  const podUid = typeof containers[0].pod_uid === "string" ? containers[0].pod_uid : null;
  const nodeName = containers[0].node;
  const node = (Array.isArray(l.nodes) ? l.nodes : []).find((n) => n && n.node === nodeName) ?? null;
  return { pod_uid: podUid, containers, node };
}
