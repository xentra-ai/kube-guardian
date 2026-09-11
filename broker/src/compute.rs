//! Compute-contention findings engine (design D3, D6, D7).
//!
//! Pure functions over row slices: the handler in `compute_api.rs` loads
//! the last [`WINDOW_MINUTES`] of `pod_compute_history` and
//! `pod_contention_history` plus the `node_compute_latest` rows and hands
//! them here; nothing in this module touches a connection, so every rule
//! is table-tested with hand-built rows.
//!
//! The rules, literally from the design:
//!
//! - **`cpu-throttled`** (D3): `throttled_usec / (nr_periods x period)`
//!   over the window >= `throttled_ratio`. The pod is under-provisioned
//!   by its own limit; no culprit. Evaluated FIRST so a throttled pod is
//!   never also blamed on a neighbour.
//! - **`noisy-neighbor`** (D6): all three of (1) victim stalled — cpu
//!   PSI some >= `stall_some` OR runq p99 >= `runq_p99_ms`, in at least
//!   [`SUSTAIN_MINUTES`] consecutive minute rows; (2) throttled ratio <
//!   `throttled_ratio_max`; (3) a cgroup C != V on the same node whose
//!   share of V's wait over the window is >= `blame_share` AND (for a
//!   pod) whose own CPU usage over the window exceeds its request, or it
//!   has none. A `system` / `kernel` culprit is named as-is. An
//!   `unknown`-dominated blame list names nobody.
//! - **`cpu-contended`**: (1) and (2) hold but no C passes (3).
//! - **`memory-pressure`**: victim memory PSI some >= `mem_stall_some`
//!   or refaulting at >= `refault_per_min` (sustained) WHILE the node's memory PSI some >=
//!   [`NODE_MEM_SOME_PCT`]. Culprit (heuristic, labelled as such in the
//!   message): the container on the node with the largest
//!   `current - request` that also grew over the window and holds >=
//!   [`MEM_CULPRIT_OVERAGE_SHARE`] of the node's total overage.
//! - **`memory-limit-thrash`**: the memory analogue of `cpu-throttled` —
//!   the victim is hitting its OWN limit (`memory.events` high/max
//!   rising, sustained) and thrashing (PSI or refaults) while the node is
//!   NOT under pressure. No culprit; raise the limit.
//!
//! Severity (D6): `critical` if cpu PSI full >= 10% or runq p99 >=
//! 200 ms (memory: an OOM kill or memory PSI full >= 10%); `high` if the
//! stall condition holds on both signals; `medium` otherwise.
//! `cpu-throttled` is `high` when the pod is also stalled (it is
//! measurably suffering, not just accounting-throttled), else `medium`.

use std::collections::{BTreeMap, HashMap};

use chrono::NaiveDateTime;

use crate::compute_types::{
    Finding, FindingCulprit, FindingEvidence, FindingKind, FindingVictim, NodeComputeLatest,
    PodComputeHistoryRow, PodContentionRow, Severity,
};

/// History window the rules evaluate over, in minutes.
pub const WINDOW_MINUTES: i64 = 5;
/// A stall must hold in this many CONSECUTIVE minute rows to count. A
/// single-minute spike is what a GC pause or a rollout looks like, not
/// starvation.
pub const SUSTAIN_MINUTES: usize = 2;
/// cpu PSI full avg10 (percent) at or above which a CPU finding is
/// `critical`: every task in the cgroup was waiting for a tenth of the
/// time.
pub const CRITICAL_CPU_FULL_PCT: f64 = 10.0;
/// runq p99 (µs) at or above which a CPU finding is `critical`.
pub const CRITICAL_RUNQ_P99_US: i64 = 200_000;
/// memory PSI full avg10 (percent) at or above which a memory finding is
/// `critical`.
pub const CRITICAL_MEM_FULL_PCT: f64 = 10.0;
/// Node `/proc/pressure/memory` some avg10 (percent) at or above which the
/// node counts as under memory pressure (D6).
pub const NODE_MEM_SOME_PCT: f64 = 5.0;
/// Share of the node's total memory overage a container must hold to be
/// named as the memory culprit (D6).
pub const MEM_CULPRIT_OVERAGE_SHARE: f64 = 0.40;

/// Tunable thresholds, from `COMPUTE_THRESHOLD_*` (chart
/// `compute.thresholds.*`). Defaults are the contract's.
#[derive(Debug, Clone, PartialEq)]
pub struct ComputeThresholds {
    /// cpu PSI some avg10, percent.
    pub stall_some: f64,
    /// runq p99, milliseconds.
    pub runq_p99_ms: f64,
    /// `cpu-throttled` fires at or above this throttled ratio.
    pub throttled_ratio: f64,
    /// Above this throttled ratio a neighbour is never blamed.
    pub throttled_ratio_max: f64,
    /// Minimum share of the victim's wait a culprit must hold.
    pub blame_share: f64,
    /// memory PSI some avg10, percent.
    pub mem_stall_some: f64,
    /// Workingset refaults per minute at or above which a container
    /// counts as thrashing. Any file-backed workload refaults a few
    /// pages a minute; `> 0` would flag every such container on a node
    /// under pressure.
    pub refault_per_min: f64,
    /// Run-queue events per minute a row must carry before its p99 counts
    /// as a stall. A p99 over a handful of wakeups (a CSI sidecar that
    /// woke 12 times in a minute) is noise, not starvation; the overflow
    /// bucket is exempt because any multi-second wait is real.
    pub min_runq_events: f64,
}

impl Default for ComputeThresholds {
    fn default() -> Self {
        ComputeThresholds {
            stall_some: 20.0,
            runq_p99_ms: 20.0,
            throttled_ratio: 0.25,
            throttled_ratio_max: 0.10,
            blame_share: 0.40,
            mem_stall_some: 10.0,
            refault_per_min: 1000.0,
            min_runq_events: 50.0,
        }
    }
}

impl ComputeThresholds {
    /// Read every threshold from its env var, falling back per-field to
    /// the default. Trimmed before parse (operator-paste defence, same as
    /// the retention env vars); a value that does not parse keeps the
    /// default rather than disabling the rule.
    pub fn from_env() -> Self {
        let d = ComputeThresholds::default();
        ComputeThresholds {
            stall_some: env_f64("COMPUTE_THRESHOLD_STALL_SOME", d.stall_some),
            runq_p99_ms: env_f64("COMPUTE_THRESHOLD_RUNQ_P99_MS", d.runq_p99_ms),
            throttled_ratio: env_f64("COMPUTE_THRESHOLD_THROTTLED_RATIO", d.throttled_ratio),
            throttled_ratio_max: env_f64(
                "COMPUTE_THRESHOLD_THROTTLED_RATIO_MAX",
                d.throttled_ratio_max,
            ),
            blame_share: env_f64("COMPUTE_THRESHOLD_BLAME_SHARE", d.blame_share),
            mem_stall_some: env_f64("COMPUTE_THRESHOLD_MEM_STALL_SOME", d.mem_stall_some),
            refault_per_min: env_f64("COMPUTE_THRESHOLD_REFAULT_PER_MIN", d.refault_per_min),
            min_runq_events: env_f64("COMPUTE_THRESHOLD_MIN_RUNQ_EVENTS", d.min_runq_events),
        }
    }
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .unwrap_or(default)
}

/// Evaluate every rule for every container that has history in the
/// window. `history` may hold rows for containers in any namespace — the
/// cross-namespace rows are what make culprit eligibility (D6 condition
/// 3) checkable; findings are emitted only for containers that are
/// victims, and the caller filters by namespace / node afterwards.
///
/// Rows are grouped by `container_uid` and sorted by `ts` here, so the
/// caller's ordering does not matter. Output order is deterministic
/// (by container_uid, then rule order) so repeated polls do not reshuffle
/// the UI.
pub fn compute_findings(
    history: &[PodComputeHistoryRow],
    pairs: &[PodContentionRow],
    nodes: &[NodeComputeLatest],
    t: &ComputeThresholds,
) -> Vec<Finding> {
    let mut by_container: BTreeMap<&str, Vec<&PodComputeHistoryRow>> = BTreeMap::new();
    for r in history {
        by_container
            .entry(r.container_uid.as_str())
            .or_default()
            .push(r);
    }
    for rows in by_container.values_mut() {
        rows.sort_by_key(|r| r.ts);
    }
    let mut pairs_by_victim: HashMap<&str, Vec<&PodContentionRow>> = HashMap::new();
    for p in pairs {
        pairs_by_victim
            .entry(p.victim_container_uid.as_str())
            .or_default()
            .push(p);
    }
    let node_mem_some: HashMap<&str, f64> = nodes
        .iter()
        .map(|n| (n.node.as_str(), n.mem_some10))
        .collect();

    let mut out = Vec::new();
    for (uid, rows) in &by_container {
        let victim_pairs = pairs_by_victim.get(uid).map(Vec::as_slice).unwrap_or(&[]);
        let node_mem = node_mem_some
            .get(rows[0].node.as_str())
            .copied()
            .unwrap_or(0.0);
        if let Some(f) = cpu_finding(rows, victim_pairs, &by_container, t) {
            out.push(f);
        }
        if let Some(f) = memory_finding(rows, node_mem, &by_container, t) {
            out.push(f);
        }
    }
    out
}

/// The span over which a predicate held for at least `SUSTAIN_MINUTES`
/// consecutive rows: `(first_ts, last_ts)` of rows satisfying it, or
/// `None` if no run was long enough.
fn sustained<F>(rows: &[&PodComputeHistoryRow], pred: F) -> Option<(NaiveDateTime, NaiveDateTime)>
where
    F: Fn(&PodComputeHistoryRow) -> bool,
{
    let mut run = 0usize;
    let mut qualified = false;
    let mut first: Option<NaiveDateTime> = None;
    let mut last: Option<NaiveDateTime> = None;
    for r in rows {
        if pred(r) {
            run += 1;
            if run >= SUSTAIN_MINUTES {
                qualified = true;
            }
            if first.is_none() {
                first = Some(r.ts);
            }
            last = Some(r.ts);
        } else {
            run = 0;
        }
    }
    if qualified {
        Some((first?, last?))
    } else {
        None
    }
}

/// Run-queue events per minute on a history row, resolution-aware so a
/// 5-minute row is judged by the same bar as a minute row.
fn runq_events_per_min(r: &PodComputeHistoryRow) -> f64 {
    let minutes = (r.resolution_secs.max(60) as f64) / 60.0;
    r.runq_count.unwrap_or(0) as f64 / minutes
}

/// `throttled_usec / (nr_periods x period_usec)` over the window. 0 when
/// there were no periods (no quota, or no data).
fn throttled_ratio(rows: &[&PodComputeHistoryRow]) -> f64 {
    let throttled: i128 = rows.iter().map(|r| r.cpu_throttled_usec as i128).sum();
    let wall: i128 = rows
        .iter()
        .map(|r| r.cpu_nr_periods as i128 * r.cpu_period_usec as i128)
        .sum();
    if wall <= 0 {
        0.0
    } else {
        (throttled as f64 / wall as f64).clamp(0.0, 1.0)
    }
}

/// Refaults per minute for one row, whatever its resolution.
fn refault_rate_per_min(r: &PodComputeHistoryRow) -> f64 {
    let minutes = (f64::from(r.resolution_secs.max(1)) / 60.0).max(1.0 / 60.0);
    r.mem_refault as f64 / minutes
}

fn victim_of(rows: &[&PodComputeHistoryRow]) -> FindingVictim {
    let r = rows[rows.len() - 1];
    FindingVictim {
        pod_uid: r.pod_uid.clone(),
        namespace: r.namespace.clone(),
        pod_name: r.pod_name.clone(),
        container: r.container.clone(),
        container_uid: r.container_uid.clone(),
        node: r.node.clone(),
    }
}

fn evidence_of(rows: &[&PodComputeHistoryRow], node_mem: f64) -> FindingEvidence {
    FindingEvidence {
        window_minutes: WINDOW_MINUTES,
        cpu_psi_some10_max: rows
            .iter()
            .map(|r| r.cpu_psi_some10_max)
            .fold(0.0, f64::max),
        cpu_psi_full10_max: rows
            .iter()
            .map(|r| r.cpu_psi_full10_max)
            .fold(0.0, f64::max),
        runq_p99_us_max: rows.iter().filter_map(|r| r.runq_p99_us).max(),
        throttled_ratio: throttled_ratio(rows),
        mem_psi_some10_max: rows
            .iter()
            .map(|r| r.mem_psi_some10_max)
            .fold(0.0, f64::max),
        node_mem_some10_max: node_mem,
        refault_delta: rows.iter().map(|r| r.mem_refault).sum(),
        mem_events_high_delta: rows.iter().map(|r| r.mem_events_high).sum(),
    }
}

fn pct(share: f64) -> String {
    format!("{}%", (share * 100.0).round() as i64)
}

fn cores(millis: f64) -> String {
    format!("{:.1}", millis / 1000.0)
}

fn mib(bytes: i64) -> String {
    format!("{}", bytes / (1024 * 1024))
}

/// `(namespace, pod)` from a `ns/pod/container` culprit ref; both `None`
/// for any other shape.
fn ns_pod(reference: &str) -> (Option<String>, Option<String>) {
    let mut parts = reference.split('/');
    match (parts.next(), parts.next()) {
        (Some(ns), Some(pod)) => (Some(ns.to_string()), Some(pod.to_string())),
        _ => (None, None),
    }
}

/// `ns/pod` for a message, from a culprit ref of the `ns/pod/container`
/// or `pod:<uid8>` shape.
fn pod_label(reference: &str) -> String {
    let mut parts = reference.split('/');
    match (parts.next(), parts.next()) {
        (Some(ns), Some(pod)) => format!("{ns}/{pod}"),
        _ => reference.to_string(),
    }
}

// ---------------------------------------------------------------------
// CPU rules
// ---------------------------------------------------------------------

/// A culprit's summed wait over the window, keyed on its identity.
struct BlameTotal<'a> {
    kind: &'a str,
    reference: &'a str,
    container_uid: Option<&'a str>,
    wait_ns: i128,
}

fn cpu_finding(
    rows: &[&PodComputeHistoryRow],
    victim_pairs: &[&PodContentionRow],
    all: &BTreeMap<&str, Vec<&PodComputeHistoryRow>>,
    t: &ComputeThresholds,
) -> Option<Finding> {
    let victim = victim_of(rows);
    let ratio = throttled_ratio(rows);
    let psi_span = sustained(rows, |r| r.cpu_psi_some10_avg >= t.stall_some);
    // A wait that lands in the histogram's overflow bucket (>= 2^23 µs,
    // ~8.4 s) has no finite quantile: the controller reports p99 and
    // max_us from the finite buckets only, so a victim whose waits are
    // ALL that long would show p99 = max = 0. Any overflow is a stall,
    // and a critical one.
    let runq_span = sustained(rows, |r| {
        let enough_events = runq_events_per_min(r) >= t.min_runq_events;
        (enough_events
            && r.runq_p99_us
                .is_some_and(|p| p as f64 >= t.runq_p99_ms * 1000.0))
            || r.runq_overflow.is_some_and(|o| o > 0)
    });
    let overflowed = rows.iter().any(|r| r.runq_overflow.is_some_and(|o| o > 0));
    let stalled = psi_span.is_some() || runq_span.is_some();
    let evidence = evidence_of(rows, 0.0);

    // D3 first: a pod throttled by its own limit is under-provisioned,
    // never a noisy-neighbour victim.
    if ratio >= t.throttled_ratio {
        let (first, last) = (rows[0].ts, rows[rows.len() - 1].ts);
        let limit = rows[rows.len() - 1]
            .cpu_limit_millis
            .map(|m| format!("limit {} cores", cores(m as f64)))
            .unwrap_or_else(|| "quota set".to_string());
        let message = format!(
            "{}/{} is throttled by its own CPU limit {} of the time ({}); raise or remove the limit.",
            victim.namespace,
            victim.pod_name,
            pct(ratio),
            limit
        );
        return Some(Finding {
            kind: FindingKind::CpuThrottled,
            severity: if stalled {
                Severity::High
            } else {
                Severity::Medium
            },
            victim,
            culprit: None,
            evidence,
            first_seen: first,
            last_seen: last,
            message,
        });
    }

    if !stalled || ratio >= t.throttled_ratio_max {
        return None;
    }

    let first_seen = [psi_span, runq_span].iter().flatten().map(|s| s.0).min()?;
    let last_seen = [psi_span, runq_span].iter().flatten().map(|s| s.1).max()?;
    let severity = if evidence.cpu_psi_full10_max >= CRITICAL_CPU_FULL_PCT
        || overflowed
        || evidence
            .runq_p99_us_max
            .is_some_and(|p| p >= CRITICAL_RUNQ_P99_US)
    {
        Severity::Critical
    } else if psi_span.is_some() && runq_span.is_some() {
        Severity::High
    } else {
        Severity::Medium
    };

    let who = format!("{}/{}", victim.namespace, victim.pod_name);
    let contended = |message: String| Finding {
        kind: FindingKind::CpuContended,
        severity,
        victim: victim.clone(),
        culprit: None,
        evidence: evidence.clone(),
        first_seen,
        last_seen,
        message,
    };

    // Sum the victim's wait per culprit, excluding itself (threads of
    // the same cgroup preempting each other are not a neighbour).
    let mut totals: Vec<BlameTotal> = Vec::new();
    let mut total_wait: i128 = 0;
    let mut unknown_wait: i128 = 0;
    for p in victim_pairs {
        if p.culprit_container_uid.as_deref() == Some(victim.container_uid.as_str()) {
            continue;
        }
        let w = p.wait_ns.max(0) as i128;
        total_wait += w;
        if p.culprit_kind == "unknown" {
            unknown_wait += w;
        }
        match totals.iter_mut().find(|b| {
            b.kind == p.culprit_kind
                && b.reference == p.culprit_ref
                && b.container_uid == p.culprit_container_uid.as_deref()
        }) {
            Some(b) => b.wait_ns += w,
            None => totals.push(BlameTotal {
                kind: &p.culprit_kind,
                reference: &p.culprit_ref,
                container_uid: p.culprit_container_uid.as_deref(),
                wait_ns: w,
            }),
        }
    }
    if total_wait <= 0 {
        return Some(contended(format!(
            "{who} is starved for CPU on node {} and no scheduler blame data is available; \
             the node is oversubscribed or the contention probe is off.",
            victim.node
        )));
    }
    let unknown_share = unknown_wait as f64 / total_wait as f64;
    if unknown_share >= t.blame_share {
        return Some(contended(format!(
            "{who} is starved for CPU on node {} but {} of its wait is unattributed, so no culprit is named.",
            victim.node,
            pct(unknown_share)
        )));
    }
    totals.sort_by_key(|a| std::cmp::Reverse(a.wait_ns));
    let Some(top) = totals.iter().find(|b| b.kind != "unknown") else {
        return Some(contended(format!(
            "{who} is starved for CPU on node {} and no neighbour dominates its wait; the node is oversubscribed.",
            victim.node
        )));
    };
    let share = top.wait_ns as f64 / total_wait as f64;
    if share < t.blame_share {
        return Some(contended(format!(
            "{who} is starved for CPU on node {} and no neighbour dominates its wait \
             (top {} at {}); the node is oversubscribed.",
            victim.node,
            pod_label(top.reference),
            pct(share)
        )));
    }

    let (culprit, message) = match top.kind {
        "pod" => {
            // D6 condition 3, second half: a pod inside its request is
            // entitled to that CPU. Needs the culprit's own rows.
            //
            // Two ways to have none, treated differently (D9):
            // - no `container_uid` at all: an untracked cgroup the
            //   controller could only name as `pod:<uid8>` (excluded
            //   namespace, not yet registered). Nothing is known about
            //   it, so it is not named — `cpu-contended` says why.
            // - a `container_uid` but no rows in the window: the pod is
            //   opted out of sampling (`kguardian.dev/compute: "off"`).
            //   Opt-out is explicitly NOT a shield against being named
            //   as a culprit, so it stays eligible with usage unknown.
            let Some(cuid) = top.container_uid else {
                return Some(contended(format!(
                    "{who} is starved for CPU on node {}; {} tops its wait ({}) but is not \
                     tracked, so its usage against its request cannot be checked.",
                    victim.node,
                    pod_label(top.reference),
                    pct(share)
                )));
            };
            let Some(crows) = all.get(cuid) else {
                let (ns, pod) = ns_pod(top.reference);
                let label = pod_label(top.reference);
                let message = format!(
                    "{who} is starved for CPU by {label} ({} of its wait); {label} is opted out of \
                     compute sampling, so its usage was not checked.",
                    pct(share)
                );
                let culprit = FindingCulprit {
                    kind: "pod".to_string(),
                    reference: top.reference.to_string(),
                    pod_uid: cuid.split('/').next().map(String::from),
                    namespace: ns,
                    pod_name: pod,
                    container_uid: Some(cuid.to_string()),
                    blame_share: share,
                    cpu_usage_millis: None,
                    cpu_request_millis: None,
                };
                return Some(Finding {
                    kind: FindingKind::NoisyNeighbor,
                    severity,
                    victim,
                    culprit: Some(culprit),
                    evidence,
                    first_seen,
                    last_seen,
                    message,
                });
            };
            let usage =
                crows.iter().map(|r| r.cpu_usage_millis_avg).sum::<f64>() / crows.len() as f64;
            let last = crows[crows.len() - 1];
            let request = last.cpu_request_millis;
            let eligible = request.is_none_or(|r| usage > r as f64);
            if !eligible {
                return Some(contended(format!(
                    "{who} is starved for CPU on node {}; {}/{} tops its wait ({}) but is running \
                     inside its {}-core CPU request, so the node is oversubscribed.",
                    victim.node,
                    last.namespace,
                    last.pod_name,
                    pct(share),
                    cores(request.unwrap_or(0) as f64)
                )));
            }
            let against = match request {
                Some(r) => format!("against a {}-core request", cores(r as f64)),
                None => "with no CPU request set".to_string(),
            };
            let message = format!(
                "{who} is starved for CPU by {}/{} ({} of its wait); {} is using {} cores {}.",
                last.namespace,
                last.pod_name,
                pct(share),
                last.pod_name,
                cores(usage),
                against
            );
            (
                FindingCulprit {
                    kind: "pod".to_string(),
                    reference: top.reference.to_string(),
                    pod_uid: Some(last.pod_uid.clone()),
                    namespace: Some(last.namespace.clone()),
                    pod_name: Some(last.pod_name.clone()),
                    container_uid: Some(last.container_uid.clone()),
                    blame_share: share,
                    cpu_usage_millis: Some(usage),
                    cpu_request_millis: request,
                },
                message,
            )
        }
        "system" | "kernel" => (
            FindingCulprit {
                kind: top.kind.to_string(),
                reference: top.reference.to_string(),
                pod_uid: None,
                namespace: None,
                pod_name: None,
                container_uid: None,
                blame_share: share,
                cpu_usage_millis: None,
                cpu_request_millis: None,
            },
            format!(
                "{who} is starved for CPU by {} ({} of its wait).",
                top.reference,
                pct(share)
            ),
        ),
        _ => {
            return Some(contended(format!(
                "{who} is starved for CPU on node {} and its wait is dominated by an unclassified \
                 cgroup ({}); the node is oversubscribed.",
                victim.node, top.reference
            )));
        }
    };

    Some(Finding {
        kind: FindingKind::NoisyNeighbor,
        severity,
        victim,
        culprit: Some(culprit),
        evidence,
        first_seen,
        last_seen,
        message,
    })
}

// ---------------------------------------------------------------------
// Memory rules
// ---------------------------------------------------------------------

fn memory_finding(
    rows: &[&PodComputeHistoryRow],
    node_mem: f64,
    all: &BTreeMap<&str, Vec<&PodComputeHistoryRow>>,
    t: &ComputeThresholds,
) -> Option<Finding> {
    let victim = victim_of(rows);
    let psi_span = sustained(rows, |r| r.mem_psi_some10_avg >= t.mem_stall_some);
    let refault_span = sustained(rows, |r| refault_rate_per_min(r) >= t.refault_per_min);
    let stalled = psi_span.is_some() || refault_span.is_some();
    if !stalled {
        return None;
    }
    let evidence = evidence_of(rows, node_mem);
    let first_seen = [psi_span, refault_span]
        .iter()
        .flatten()
        .map(|s| s.0)
        .min()?;
    let last_seen = [psi_span, refault_span]
        .iter()
        .flatten()
        .map(|s| s.1)
        .max()?;
    let oom: i64 = rows.iter().map(|r| r.mem_oom_kill).sum();
    let full_max = rows
        .iter()
        .map(|r| r.mem_psi_full10_max)
        .fold(0.0, f64::max);
    let severity = if oom > 0 || full_max >= CRITICAL_MEM_FULL_PCT {
        Severity::Critical
    } else if psi_span.is_some() && refault_span.is_some() {
        Severity::High
    } else {
        Severity::Medium
    };
    let who = format!("{}/{}", victim.namespace, victim.pod_name);
    let node_pressured = node_mem >= NODE_MEM_SOME_PCT;

    if node_pressured {
        let culprit = memory_culprit(&victim, all);
        let message = match &culprit {
            Some((c, overage)) => format!(
                "{who} is stalling on memory while node {} is under memory pressure; {} is using \
                 {} MiB over its request (heuristic: largest grown overage on the node).",
                victim.node,
                pod_label(&c.reference),
                mib(*overage)
            ),
            None => format!(
                "{who} is stalling on memory while node {} is under memory pressure; no single \
                 neighbour accounts for the node's overage.",
                victim.node
            ),
        };
        let culprit = culprit.map(|(c, _)| c);
        return Some(Finding {
            kind: FindingKind::MemoryPressure,
            severity,
            victim,
            culprit,
            evidence,
            first_seen,
            last_seen,
            message,
        });
    }

    // Node fine, victim thrashing: is it hitting its own limit?
    let last = rows[rows.len() - 1];
    let limit = last.mem_limit?;
    let limit_hits = sustained(rows, |r| r.mem_events_high + r.mem_events_max > 0)?;
    let hits: i64 = rows
        .iter()
        .map(|r| r.mem_events_high + r.mem_events_max)
        .sum();
    let message = format!(
        "{who} is thrashing under its own memory limit ({} MiB, hit {} times in {} minutes); raise the limit.",
        mib(limit),
        hits,
        WINDOW_MINUTES
    );
    Some(Finding {
        kind: FindingKind::MemoryLimitThrash,
        severity,
        victim,
        culprit: None,
        evidence,
        first_seen: first_seen.min(limit_hits.0),
        last_seen: last_seen.max(limit_hits.1),
        message,
    })
}

/// D6 memory heuristic: the container on the victim's node with the
/// largest `current - request` (a container with no request counts all
/// of its usage as overage — it reserved nothing) that also grew over the
/// window and holds at least `MEM_CULPRIT_OVERAGE_SHARE` of the node's
/// total positive overage. Returns the culprit and its overage in bytes.
fn memory_culprit(
    victim: &FindingVictim,
    all: &BTreeMap<&str, Vec<&PodComputeHistoryRow>>,
) -> Option<(FindingCulprit, i64)> {
    let mut node_overage: i128 = 0;
    let mut best: Option<(&PodComputeHistoryRow, i64)> = None;
    for (uid, rows) in all {
        let last = rows[rows.len() - 1];
        if last.node != victim.node {
            continue;
        }
        let overage = last.mem_current_last - last.mem_request.unwrap_or(0);
        if overage <= 0 {
            continue;
        }
        node_overage += overage as i128;
        if *uid == victim.container_uid.as_str() {
            continue;
        }
        let grew = rows.len() >= 2 && last.mem_current_last > rows[0].mem_current_last;
        if !grew {
            continue;
        }
        if best.is_none_or(|(_, o)| overage > o) {
            best = Some((last, overage));
        }
    }
    let (row, overage) = best?;
    if node_overage <= 0 {
        return None;
    }
    let share = overage as f64 / node_overage as f64;
    if share < MEM_CULPRIT_OVERAGE_SHARE {
        return None;
    }
    let rows = all.get(row.container_uid.as_str())?;
    let usage = rows.iter().map(|r| r.cpu_usage_millis_avg).sum::<f64>() / rows.len() as f64;
    Some((
        FindingCulprit {
            kind: "pod".to_string(),
            reference: format!("{}/{}/{}", row.namespace, row.pod_name, row.container),
            pod_uid: Some(row.pod_uid.clone()),
            namespace: Some(row.namespace.clone()),
            pod_name: Some(row.pod_name.clone()),
            container_uid: Some(row.container_uid.clone()),
            blame_share: share,
            cpu_usage_millis: Some(usage),
            cpu_request_millis: row.cpu_request_millis,
        },
        overage,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn t0() -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 9, 10)
            .unwrap()
            .and_hms_opt(2, 40, 0)
            .unwrap()
    }

    fn minute(m: i64) -> NaiveDateTime {
        t0() + chrono::Duration::minutes(m)
    }

    /// A quiet minute row for `ns/pod/container` on `node`.
    fn row(
        id: i64,
        ns: &str,
        pod: &str,
        container: &str,
        node: &str,
        m: i64,
    ) -> PodComputeHistoryRow {
        PodComputeHistoryRow {
            id,
            container_uid: format!("{pod}-uid/{container}"),
            pod_uid: format!("{pod}-uid"),
            namespace: ns.into(),
            pod_name: pod.into(),
            container: container.into(),
            node: node.into(),
            ts: minute(m),
            resolution_secs: 60,
            cpu_usage_millis_avg: 100.0,
            cpu_usage_millis_max: 120.0,
            cpu_usage_millis_last: 100.0,
            cpu_quota_usec: None,
            cpu_period_usec: 100_000,
            cpu_request_millis: Some(250),
            cpu_limit_millis: None,
            cpu_nr_periods: 600,
            cpu_nr_throttled: 0,
            cpu_throttled_usec: 0,
            cpu_psi_some10_avg: 1.0,
            cpu_psi_some10_max: 2.0,
            cpu_psi_full10_avg: 0.0,
            cpu_psi_full10_max: 0.0,
            mem_current_avg: 100 << 20,
            mem_current_max: 100 << 20,
            mem_current_last: 100 << 20,
            mem_working_set_avg: 90 << 20,
            mem_working_set_max: 90 << 20,
            mem_working_set_last: 90 << 20,
            mem_limit: None,
            mem_request: Some(128 << 20),
            mem_psi_some10_avg: 0.0,
            mem_psi_some10_max: 0.0,
            mem_psi_full10_avg: 0.0,
            mem_psi_full10_max: 0.0,
            mem_events_high: 0,
            mem_events_max: 0,
            mem_oom_kill: 0,
            mem_refault: 0,
            mem_pgmajfault: 0,
            runq_count: Some(100),
            runq_p50_us: Some(50),
            runq_p95_us: Some(500),
            runq_p99_us: Some(2_000),
            runq_max_us: Some(4_000),
            runq_overflow: Some(0),
            runq_hist: None,
        }
    }

    fn pair(
        id: i64,
        m: i64,
        victim_uid: &str,
        kind: &str,
        reference: &str,
        culprit_uid: Option<&str>,
        wait_ns: i64,
    ) -> PodContentionRow {
        PodContentionRow {
            id,
            ts: minute(m),
            node: "worker-3".into(),
            victim_container_uid: victim_uid.into(),
            victim_pod_uid: victim_uid.split('/').next().unwrap().into(),
            victim_namespace: "payments".into(),
            culprit_cgroup_id: 1,
            culprit_kind: kind.into(),
            culprit_ref: reference.into(),
            culprit_container_uid: culprit_uid.map(String::from),
            count: 10,
            wait_ns,
        }
    }

    fn node(name: &str, mem_some10: f64) -> NodeComputeLatest {
        NodeComputeLatest {
            node: name.into(),
            ts: t0(),
            interval_ms: 5000,
            ctxt_per_sec: 1000.0,
            compute_enabled: true,
            compute_supported: true,
            contention_loaded: true,
            cpu_some10: 0.0,
            cpu_full10: 0.0,
            mem_some10,
            mem_full10: 0.0,
            cpu_cores: 8,
            memory_bytes: 32 << 30,
            bpf_runq_enqueued: 0,
            bpf_runq_hist: 0,
            bpf_pair: 0,
            unknown_blame_share: 0.0,
            updated_at: t0(),
            bpf_hist_update_failures: None,
            bpf_pair_update_failures: None,
        }
    }

    const VICTIM: &str = "api-uid/api";
    const BULLY: &str = "etl-1-x-uid/worker";

    /// The design's bully/victim fixture: the victim's cpu PSI is 30% for
    /// five minutes with no throttling, the bully holds 70% of its wait,
    /// kubelet the other 30%, and the bully runs 1.9 cores on a 0.5-core
    /// request.
    fn bully_victim() -> (Vec<PodComputeHistoryRow>, Vec<PodContentionRow>) {
        let mut history = Vec::new();
        let mut pairs = Vec::new();
        for m in 0..5 {
            let mut v = row(m, "payments", "api", "api", "worker-3", m);
            v.cpu_psi_some10_avg = 30.0;
            v.cpu_psi_some10_max = 31.0;
            v.cpu_psi_full10_max = 4.2;
            v.runq_p99_us = Some(48_000);
            history.push(v);
            let mut b = row(100 + m, "batch", "etl-1-x", "worker", "worker-3", m);
            b.cpu_usage_millis_avg = 1900.0;
            b.cpu_request_millis = Some(500);
            history.push(b);
            pairs.push(pair(
                m,
                m,
                VICTIM,
                "pod",
                "batch/etl-1-x/worker",
                Some(BULLY),
                7_000_000_000,
            ));
            pairs.push(pair(
                100 + m,
                m,
                VICTIM,
                "system",
                "system.slice/kubelet.service",
                None,
                3_000_000_000,
            ));
        }
        (history, pairs)
    }

    #[test]
    fn fires_noisy_neighbor_on_bully_victim_fixture() {
        let (history, pairs) = bully_victim();
        let nodes = [node("worker-3", 0.0)];
        let findings = compute_findings(&history, &pairs, &nodes, &ComputeThresholds::default());
        assert_eq!(findings.len(), 1, "exactly one finding: {findings:#?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::NoisyNeighbor);
        assert_eq!(f.victim.container_uid, VICTIM);
        let c = f.culprit.as_ref().expect("names the bully");
        assert_eq!(c.kind, "pod");
        assert_eq!(c.container_uid.as_deref(), Some(BULLY));
        assert_eq!(c.pod_name.as_deref(), Some("etl-1-x"));
        assert!((c.blame_share - 0.7).abs() < 1e-9);
        assert_eq!(c.cpu_usage_millis, Some(1900.0));
        assert_eq!(c.cpu_request_millis, Some(500));
        // Both signals sustained, neither critical threshold crossed.
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.evidence.cpu_psi_some10_max, 31.0);
        assert_eq!(f.evidence.runq_p99_us_max, Some(48_000));
        assert_eq!(f.evidence.window_minutes, 5);
        assert_eq!(f.first_seen, minute(0));
        assert_eq!(f.last_seen, minute(4));
        assert_eq!(
            f.message,
            "payments/api is starved for CPU by batch/etl-1-x (70% of its wait); etl-1-x is using 1.9 cores against a 0.5-core request."
        );
    }

    #[test]
    fn throttled_victim_is_cpu_throttled_not_noisy_neighbor() {
        let (mut history, pairs) = bully_victim();
        // 30% of every period throttled — above throttledRatio (0.25),
        // and therefore above throttledRatioMax (0.10) too.
        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            r.cpu_limit_millis = Some(500);
            r.cpu_quota_usec = Some(50_000);
            r.cpu_throttled_usec = 600 * 100_000 * 3 / 10;
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].kind, FindingKind::CpuThrottled);
        assert!(findings[0].culprit.is_none());
        assert!((findings[0].evidence.throttled_ratio - 0.3).abs() < 1e-9);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "throttled AND stalled"
        );
        assert!(findings[0]
            .message
            .contains("throttled by its own CPU limit 30%"));
        assert!(findings[0].message.contains("limit 0.5 cores"));
        assert!(
            findings
                .iter()
                .all(|f| f.kind != FindingKind::NoisyNeighbor),
            "a self-throttled pod must never be blamed on a neighbour"
        );
    }

    #[test]
    fn throttled_between_max_and_ratio_names_nobody() {
        // 15% throttled: not enough for cpu-throttled, too much to blame
        // a neighbour (D3). Strict reading: no CPU finding at all.
        let (mut history, pairs) = bully_victim();
        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            r.cpu_throttled_usec = 600 * 100_000 * 15 / 100;
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn culprit_inside_its_request_is_cpu_contended() {
        let (mut history, pairs) = bully_victim();
        for r in history.iter_mut().filter(|r| r.container_uid == BULLY) {
            r.cpu_usage_millis_avg = 1900.0;
            r.cpu_request_millis = Some(2000);
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].kind, FindingKind::CpuContended);
        assert!(findings[0].culprit.is_none());
        assert!(findings[0]
            .message
            .contains("inside its 2.0-core CPU request"));
    }

    #[test]
    fn opted_out_culprit_with_container_uid_is_named_with_unknown_usage() {
        // D9: a pod annotated kguardian.dev/compute=off is not sampled
        // (no history rows) but resolves with a container_uid, and must
        // still be nameable as a culprit.
        let (mut history, pairs) = bully_victim();
        history.retain(|r| r.container_uid != BULLY);
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::NoisyNeighbor);
        let c = f.culprit.as_ref().expect("opted-out bully is named");
        assert_eq!(c.kind, "pod");
        assert_eq!(c.container_uid.as_deref(), Some(BULLY));
        assert_eq!(c.pod_uid.as_deref(), Some("etl-1-x-uid"));
        assert_eq!(c.namespace.as_deref(), Some("batch"));
        assert_eq!(c.pod_name.as_deref(), Some("etl-1-x"));
        assert_eq!(c.cpu_usage_millis, None);
        assert_eq!(c.cpu_request_millis, None);
        assert_eq!(
            f.message,
            "payments/api is starved for CPU by batch/etl-1-x (70% of its wait); batch/etl-1-x is opted out of compute sampling, so its usage was not checked."
        );
        let v = serde_json::to_value(c).unwrap();
        assert_eq!(v["cpu_usage_millis"], serde_json::Value::Null);
    }

    #[test]
    fn untracked_culprit_without_container_uid_is_cpu_contended() {
        let (mut history, mut pairs) = bully_victim();
        history.retain(|r| r.container_uid != BULLY);
        for p in pairs.iter_mut().filter(|p| p.culprit_kind == "pod") {
            p.culprit_container_uid = None;
            p.culprit_ref = "pod:etl1x0ab".into();
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].kind, FindingKind::CpuContended);
        assert!(findings[0].culprit.is_none());
        assert!(findings[0]
            .message
            .contains("pod:etl1x0ab tops its wait (70%) but is not tracked"));
    }

    #[test]
    fn two_thousand_containers_still_yield_the_right_finding() {
        // Scale guard for the per-container row bound: the engine must
        // reach the same verdict for one victim regardless of how many
        // other (quiet) containers share the window, as long as every
        // container keeps its own full set of minute rows.
        let (mut history, pairs) = bully_victim();
        let mut id = 10_000;
        for n in 0..2_000 {
            let node = format!("worker-{}", n % 40);
            for m in 0..5 {
                id += 1;
                history.push(row(id, "fleet", &format!("svc-{n}"), "app", &node, m));
            }
        }
        assert!(history.len() > 10_000);
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings.len(), 1, "one victim, one finding");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::NoisyNeighbor);
        assert_eq!(f.victim.container_uid, VICTIM);
        assert_eq!(
            f.culprit.as_ref().unwrap().container_uid.as_deref(),
            Some(BULLY)
        );
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn culprit_with_no_request_is_eligible() {
        let (mut history, pairs) = bully_victim();
        for r in history.iter_mut().filter(|r| r.container_uid == BULLY) {
            r.cpu_request_millis = None;
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings[0].kind, FindingKind::NoisyNeighbor);
        assert!(findings[0].message.ends_with("with no CPU request set."));
        assert_eq!(
            findings[0].culprit.as_ref().unwrap().cpu_request_millis,
            None
        );
    }

    #[test]
    fn single_minute_spike_does_not_fire() {
        let (mut history, pairs) = bully_victim();
        // Only minute 2 is stalled; every other minute is quiet.
        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            if r.ts != minute(2) {
                r.cpu_psi_some10_avg = 1.0;
                r.runq_p99_us = Some(2_000);
            }
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn two_non_consecutive_stalled_minutes_do_not_fire() {
        let (mut history, pairs) = bully_victim();
        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            if r.ts != minute(1) && r.ts != minute(3) {
                r.cpu_psi_some10_avg = 1.0;
                r.runq_p99_us = Some(2_000);
            }
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn unknown_dominated_blame_names_no_culprit() {
        let (history, mut pairs) = bully_victim();
        for p in pairs.iter_mut().filter(|p| p.culprit_kind == "pod") {
            p.culprit_kind = "unknown".into();
            p.culprit_ref = "x/y".into();
            p.culprit_container_uid = None;
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::CpuContended);
        assert!(findings[0].culprit.is_none());
        assert!(findings[0]
            .message
            .contains("70% of its wait is unattributed"));
    }

    #[test]
    fn system_culprit_is_named_as_system() {
        let (history, mut pairs) = bully_victim();
        // Swap the shares: kubelet 70%, the bully 30%.
        for p in pairs.iter_mut() {
            p.wait_ns = if p.culprit_kind == "system" {
                7_000_000_000
            } else {
                3_000_000_000
            };
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings[0].kind, FindingKind::NoisyNeighbor);
        let c = findings[0].culprit.as_ref().unwrap();
        assert_eq!(c.kind, "system");
        assert_eq!(c.reference, "system.slice/kubelet.service");
        assert_eq!(c.pod_uid, None);
        assert_eq!(
            findings[0].message,
            "payments/api is starved for CPU by system.slice/kubelet.service (70% of its wait)."
        );
    }

    #[test]
    fn no_dominant_neighbour_is_cpu_contended() {
        let (history, mut pairs) = bully_victim();
        for p in pairs.iter_mut() {
            p.wait_ns = 5_000_000_000; // 50 / 50, both above blameShare 0.40
        }
        // Top is 50% ≥ 0.40 → bully named. Push blameShare up to prove
        // the threshold is read from the struct.
        let t = ComputeThresholds {
            blame_share: 0.60,
            ..Default::default()
        };
        let findings = compute_findings(&history, &pairs, &[], &t);
        assert_eq!(findings[0].kind, FindingKind::CpuContended);
        assert!(findings[0]
            .message
            .contains("no neighbour dominates its wait"));
    }

    #[test]
    fn no_blame_data_is_cpu_contended() {
        let (history, _) = bully_victim();
        let findings = compute_findings(&history, &[], &[], &ComputeThresholds::default());
        assert_eq!(findings[0].kind, FindingKind::CpuContended);
        assert!(findings[0].message.contains("no scheduler blame data"));
    }

    #[test]
    fn runq_only_stall_fires_medium_and_full_pressure_is_critical() {
        let (mut history, pairs) = bully_victim();
        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            r.cpu_psi_some10_avg = 1.0; // PSI quiet, runq p99 48 ms ≥ 20 ms
            r.cpu_psi_full10_max = 0.0;
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings[0].kind, FindingKind::NoisyNeighbor);
        assert_eq!(findings[0].severity, Severity::Medium);

        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            r.cpu_psi_full10_max = 12.0;
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings[0].severity, Severity::Critical);

        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            r.cpu_psi_full10_max = 0.0;
            r.runq_p99_us = Some(250_000);
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn p99_over_a_handful_of_events_is_not_a_stall() {
        // PSI quiet, p99 48 ms from the fixture, but only 12 run-queue events
        // in the minute: a near-idle sidecar's wakeups, not starvation.
        let (mut history, pairs) = bully_victim();
        fn set(h: &mut [PodComputeHistoryRow], f: impl Fn(&mut PodComputeHistoryRow)) {
            h.iter_mut()
                .filter(|r| r.container_uid == VICTIM)
                .for_each(f);
        }
        set(&mut history, |r| {
            r.cpu_psi_some10_avg = 1.0;
            r.cpu_psi_full10_max = 0.0;
            r.runq_count = Some(12);
            r.runq_overflow = Some(0);
        });
        let t = ComputeThresholds::default();
        let for_victim = |f: &[Finding]| f.iter().any(|x| x.victim.container_uid == VICTIM);
        assert!(
            !for_victim(&compute_findings(&history, &pairs, &[], &t)),
            "12 events/min must not fire the p99 rule"
        );

        // The same p99 over enough events is a stall.
        set(&mut history, |r| r.runq_count = Some(120));
        assert!(
            for_victim(&compute_findings(&history, &pairs, &[], &t)),
            "120 events/min fires"
        );

        // A 5-minute row is judged per minute: 120 events over 300 s is 24/min.
        set(&mut history, |r| r.resolution_secs = 300);
        assert!(!for_victim(&compute_findings(&history, &pairs, &[], &t)));

        // Overflow is exempt from the event floor: any 8 s wait is real.
        set(&mut history, |r| r.runq_overflow = Some(1));
        assert!(for_victim(&compute_findings(&history, &pairs, &[], &t)));
    }

    #[test]
    fn probe_off_uses_psi_only() {
        let (mut history, pairs) = bully_victim();
        for r in history.iter_mut() {
            r.runq_p99_us = None;
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings[0].kind, FindingKind::NoisyNeighbor);
        assert_eq!(findings[0].evidence.runq_p99_us_max, None);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    fn memory_victim(node_mem: f64) -> (Vec<PodComputeHistoryRow>, Vec<NodeComputeLatest>) {
        let mut history = Vec::new();
        for m in 0..5 {
            let mut v = row(m, "payments", "api", "api", "worker-3", m);
            v.mem_psi_some10_avg = 20.0;
            v.mem_psi_some10_max = 25.0;
            v.mem_refault = 1500;
            history.push(v);
            // A hog: no request, growing, holds most of the node overage.
            let mut h = row(100 + m, "batch", "hog", "main", "worker-3", m);
            h.mem_request = None;
            h.mem_current_last = (2000 + 100 * m) << 20;
            history.push(h);
            // A bystander over its request but not growing.
            let mut s = row(200 + m, "web", "static", "nginx", "worker-3", m);
            s.mem_current_last = 300 << 20;
            history.push(s);
        }
        (history, vec![node("worker-3", node_mem)])
    }

    #[test]
    fn memory_pressure_requires_node_pressure() {
        let (history, nodes) = memory_victim(0.0);
        let findings = compute_findings(&history, &[], &nodes, &ComputeThresholds::default());
        assert!(
            findings
                .iter()
                .all(|f| f.kind != FindingKind::MemoryPressure),
            "node not under pressure → no memory-pressure: {findings:#?}"
        );

        let (history, nodes) = memory_victim(8.0);
        let findings = compute_findings(&history, &[], &nodes, &ComputeThresholds::default());
        let f = findings
            .iter()
            .find(|f| f.kind == FindingKind::MemoryPressure)
            .expect("fires under node pressure");
        assert_eq!(f.victim.pod_name, "api");
        let c = f.culprit.as_ref().expect("names the growing hog");
        assert_eq!(c.pod_name.as_deref(), Some("hog"));
        assert!(c.blame_share > 0.8, "hog holds most of the overage: {c:?}");
        assert_eq!(f.evidence.node_mem_some10_max, 8.0);
        assert_eq!(f.evidence.refault_delta, 7500);
        assert_eq!(f.severity, Severity::High, "PSI and refault both sustained");
        assert!(f.message.contains("batch/hog is using"));
        // No thrash finding for the same victim while the node is hot.
        assert!(findings
            .iter()
            .all(|f| f.kind != FindingKind::MemoryLimitThrash));
    }

    #[test]
    fn memory_pressure_without_grown_culprit_names_nobody() {
        let (mut history, nodes) = memory_victim(8.0);
        for r in history.iter_mut().filter(|r| r.pod_name == "hog") {
            r.mem_current_last = 2000 << 20; // flat
        }
        let findings = compute_findings(&history, &[], &nodes, &ComputeThresholds::default());
        let f = findings
            .iter()
            .find(|f| f.kind == FindingKind::MemoryPressure)
            .unwrap();
        assert!(f.culprit.is_none());
        assert!(f.message.contains("no single neighbour"));
    }

    fn thrash_victim(node_mem: f64) -> (Vec<PodComputeHistoryRow>, Vec<NodeComputeLatest>) {
        let mut history = Vec::new();
        for m in 0..5 {
            let mut v = row(m, "payments", "api", "api", "worker-3", m);
            v.mem_limit = Some(256 << 20);
            v.mem_events_high = 3;
            v.mem_refault = 5000;
            history.push(v);
        }
        (history, vec![node("worker-3", node_mem)])
    }

    #[test]
    fn memory_limit_thrash_requires_node_not_under_pressure() {
        let (history, nodes) = thrash_victim(0.0);
        let findings = compute_findings(&history, &[], &nodes, &ComputeThresholds::default());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::MemoryLimitThrash);
        assert!(f.culprit.is_none());
        assert_eq!(f.evidence.mem_events_high_delta, 15);
        assert_eq!(
            f.message,
            "payments/api is thrashing under its own memory limit (256 MiB, hit 15 times in 5 minutes); raise the limit."
        );

        let (history, nodes) = thrash_victim(8.0);
        let findings = compute_findings(&history, &[], &nodes, &ComputeThresholds::default());
        assert!(
            findings
                .iter()
                .all(|f| f.kind != FindingKind::MemoryLimitThrash),
            "node under pressure → memory-pressure, not thrash: {findings:#?}"
        );
        assert_eq!(findings[0].kind, FindingKind::MemoryPressure);
    }

    #[test]
    fn memory_limit_thrash_needs_a_limit_and_limit_hits() {
        let (mut history, nodes) = thrash_victim(0.0);
        for r in history.iter_mut() {
            r.mem_events_high = 0;
        }
        let findings = compute_findings(&history, &[], &nodes, &ComputeThresholds::default());
        assert!(
            findings.is_empty(),
            "refaults without limit hits: {findings:#?}"
        );

        let (mut history, nodes) = thrash_victim(0.0);
        for r in history.iter_mut() {
            r.mem_limit = None;
        }
        let findings = compute_findings(&history, &[], &nodes, &ComputeThresholds::default());
        assert!(
            findings.is_empty(),
            "no limit → nothing to raise: {findings:#?}"
        );
    }

    #[test]
    fn oom_kill_makes_memory_finding_critical() {
        let (mut history, nodes) = thrash_victim(0.0);
        history[4].mem_oom_kill = 1;
        let findings = compute_findings(&history, &[], &nodes, &ComputeThresholds::default());
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn quiet_cluster_has_no_findings() {
        let history: Vec<_> = (0..5)
            .map(|m| row(m, "payments", "api", "api", "worker-3", m))
            .collect();
        let findings = compute_findings(
            &history,
            &[],
            &[node("worker-3", 0.0)],
            &ComputeThresholds::default(),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn runq_overflow_counts_as_a_critical_stall() {
        // Every wait in the overflow bucket: finite quantiles read 0.
        let (mut history, pairs) = bully_victim();
        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            r.cpu_psi_some10_avg = 1.0;
            r.cpu_psi_full10_max = 0.0;
            r.runq_p99_us = Some(0);
            r.runq_max_us = Some(0);
            r.runq_overflow = Some(3);
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].kind, FindingKind::NoisyNeighbor);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].evidence.runq_p99_us_max, Some(0));

        // A single overflow minute is still subject to the sustain rule.
        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            r.runq_overflow = if r.ts == minute(2) { Some(3) } else { Some(0) };
        }
        let findings = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn low_refault_rate_alone_is_not_memory_pressure() {
        // A file-backed workload refaulting a few hundred pages a minute
        // on a pressured node, with no memory PSI: below refaultPerMin
        // (1 000) it is background noise, not thrash.
        let (mut history, nodes) = memory_victim(8.0);
        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            r.mem_psi_some10_avg = 0.0;
            r.mem_psi_some10_max = 0.0;
            r.mem_refault = 300;
        }
        let findings = compute_findings(&history, &[], &nodes, &ComputeThresholds::default());
        assert!(findings.is_empty(), "{findings:#?}");

        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            r.mem_refault = 1000;
        }
        let findings = compute_findings(&history, &[], &nodes, &ComputeThresholds::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::MemoryPressure);
        assert_eq!(
            findings[0].severity,
            Severity::Medium,
            "refault only, no PSI"
        );

        // The rate is per minute: the same count on a 5-minute row is 5x
        // lower and must not fire.
        for r in history.iter_mut().filter(|r| r.container_uid == VICTIM) {
            r.resolution_secs = 300;
        }
        let findings = compute_findings(&history, &[], &nodes, &ComputeThresholds::default());
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn thresholds_parse_from_env_with_defaults() {
        let _guard = crate::test_support::env_lock();
        let keys = [
            "COMPUTE_THRESHOLD_STALL_SOME",
            "COMPUTE_THRESHOLD_RUNQ_P99_MS",
            "COMPUTE_THRESHOLD_THROTTLED_RATIO",
            "COMPUTE_THRESHOLD_THROTTLED_RATIO_MAX",
            "COMPUTE_THRESHOLD_BLAME_SHARE",
            "COMPUTE_THRESHOLD_MEM_STALL_SOME",
            "COMPUTE_THRESHOLD_REFAULT_PER_MIN",
            "COMPUTE_THRESHOLD_MIN_RUNQ_EVENTS",
        ];
        let prev: Vec<Option<String>> = keys.iter().map(|k| std::env::var(k).ok()).collect();
        for k in keys {
            std::env::remove_var(k);
        }
        assert_eq!(ComputeThresholds::from_env(), ComputeThresholds::default());
        let d = ComputeThresholds::default();
        assert_eq!(d.stall_some, 20.0);
        assert_eq!(d.runq_p99_ms, 20.0);
        assert_eq!(d.throttled_ratio, 0.25);
        assert_eq!(d.throttled_ratio_max, 0.10);
        assert_eq!(d.blame_share, 0.40);
        assert_eq!(d.mem_stall_some, 10.0);
        assert_eq!(d.refault_per_min, 1000.0);
        assert_eq!(d.min_runq_events, 50.0);

        std::env::set_var("COMPUTE_THRESHOLD_STALL_SOME", " 35 \n");
        std::env::set_var("COMPUTE_THRESHOLD_BLAME_SHARE", "0.6");
        std::env::set_var("COMPUTE_THRESHOLD_RUNQ_P99_MS", "garbage");
        std::env::set_var("COMPUTE_THRESHOLD_MEM_STALL_SOME", "-1");
        std::env::set_var("COMPUTE_THRESHOLD_REFAULT_PER_MIN", "250");
        std::env::set_var("COMPUTE_THRESHOLD_MIN_RUNQ_EVENTS", "10");
        let t = ComputeThresholds::from_env();
        assert_eq!(t.refault_per_min, 250.0);
        assert_eq!(t.min_runq_events, 10.0);
        assert_eq!(t.stall_some, 35.0, "trimmed");
        assert_eq!(t.blame_share, 0.6);
        assert_eq!(t.runq_p99_ms, 20.0, "unparseable keeps the default");
        assert_eq!(t.mem_stall_some, 10.0, "negative keeps the default");
        assert_eq!(t.throttled_ratio, 0.25);

        for (k, v) in keys.iter().zip(prev) {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn output_is_ordered_and_scoped_to_victims() {
        // Two victims on two nodes; the bully must not get a finding of
        // its own and the order must be stable across calls.
        let (mut history, mut pairs) = bully_victim();
        for m in 0..5 {
            let mut v = row(300 + m, "web", "front", "app", "worker-4", m);
            v.cpu_psi_some10_avg = 40.0;
            history.push(v);
            let mut p = pair(
                300 + m,
                m,
                "front-uid/app",
                "kernel",
                "kernel",
                None,
                1_000_000_000,
            );
            p.node = "worker-4".into();
            history.push(row(400 + m, "batch", "etl-1-x", "sidecar", "worker-3", m));
            pairs.push(p);
        }
        let a = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        let b = compute_findings(&history, &pairs, &[], &ComputeThresholds::default());
        assert_eq!(a, b);
        let victims: Vec<_> = a.iter().map(|f| f.victim.container_uid.as_str()).collect();
        assert_eq!(victims, vec![VICTIM, "front-uid/app"]);
        assert_eq!(a[1].culprit.as_ref().unwrap().kind, "kernel");
    }
}
