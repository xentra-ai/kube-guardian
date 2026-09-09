//! Memory admission control for whole-result-set reads.
//!
//! # The defect this exists to fix
//!
//! The broker was OOMKilled in the dev cluster (exit 137, `limits.memory:
//! 1Gi`) serving concurrent reads. No single request was too large — the
//! `clamp_pod_traffic_limit` hard cap already bounds one request. What was
//! missing is that **nothing connected the concurrency bound to the memory
//! limit**:
//!
//! - `DB_POOL_MAX_SIZE` (default 32) is what actually bounds how many
//!   requests can be materialising a result set at once. It was chosen for
//!   DB contention and never referenced memory at all.
//! - One `GET /pod/traffic?limit=20000` peaks at ~50 MiB in flight (see
//!   [`TRAFFIC_ROW_COST_BYTES`] for the byte-exact derivation).
//! - 32 x 50 MiB = 1.6 GB against a 1 GiB limit. The broker rests at
//!   330-368 MiB (`kubectl top`, two readings on the same day), leaving only
//!   ~656-694 MiB of real headroom — about 13 concurrent heavy reads, not 32.
//!
//! So the system permitted roughly twice as many simultaneous whole-result-set
//! reads as its memory could hold, and no layer was aware of it.
//!
//! # The fix
//!
//! A semaphore denominated in **KiB of estimated in-flight response**, sized
//! from an explicit memory budget, acquired by every handler that
//! materialises a whole result set and held until the response body has been
//! built.
//!
//! Bytes, not request count, is the unit that matters: a 20000-row traffic
//! read costs ~100x a 100-row audit read, so a count-based semaphore would
//! either throttle cheap reads pointlessly or fail to bound expensive ones.
//! A byte budget lets many small reads run concurrently while still capping
//! the aggregate — which is the quantity the OOM killer actually watches.
//!
//! This mirrors the existing `AUDIT_INFLIGHT_PERMITS` semaphore in
//! [`crate::audit`] — same pattern, different unit.
//!
//! # Why not the alternatives
//!
//! - **Stream the response instead of materialising it.** actix supports
//!   streaming bodies, but diesel does not stream: libpq materialises the
//!   entire `PGresult` in memory before diesel converts it row-by-row, so
//!   streaming removes the `Vec` and the contiguous body (~76% of the peak)
//!   but leaves the libpq buffer untouched — and it would pin a pool
//!   connection for the full lifetime of a slow client's download, trading a
//!   memory bound for a connection-starvation bound. Worth doing later behind
//!   a server-side cursor; it does not remove the need for this bound.
//! - **Lower the hard row cap.** Does not fix the concurrency-vs-memory
//!   disconnect (N concurrent reads at any cap is still unbounded in
//!   aggregate), and it silently truncates the advisor's cluster-wide read —
//!   producing a policy with missing rules, which is precisely the failure
//!   this project exists to prevent.
//! - **Derive the pool size from a memory budget.** The pool is a DB-contention
//!   knob; conflating it with memory makes both untunable, and it would
//!   throttle cheap traffic (health checks, ingest inserts, per-pod frontend
//!   reads) that costs no meaningful memory. The startup coherence check in
//!   [`ReadBudget::from_env`] gets the useful half of this idea without the
//!   coupling.
//!
//! # What it does NOT do
//!
//! It never truncates. A read that cannot fit the budget within
//! [`DEFAULT_ACQUIRE_WAIT_MS`] is refused with `503` + `Retry-After`, an
//! explicit and observable signal, and is counted in
//! `broker_read_shed_total`. A short read that looked like success would
//! produce a silently incomplete policy — strictly worse than an error.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use actix_web::HttpResponse;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};

/// Peak in-flight heap per `pod_traffic` row, in bytes.
///
/// Derived — not guessed — from `tests/read_memory_profile.rs`, a byte-exact
/// counting global allocator run over the real response path at the 20000-row
/// hard cap:
///
/// ```text
/// Vec<PodTraffic> resident      :  13.80 MiB  ( 723.5 B/row)
/// JSON body (final length)      :  10.91 MiB  ( 572.1 B/row)
/// serialise peak (body + Vec)   :  24.00 MiB
/// PEAK in flight (Vec + serial.):  37.80 MiB  (1981.8 B/row)
/// ```
///
/// The serialise peak is 2.2x the finished body because
/// `HttpResponseBuilder::json` grows one contiguous buffer by doubling while
/// the `Vec` is still alive — at the final doubling the old buffer, the new
/// buffer and the `Vec` are all resident at once.
///
/// On top of the 1982 B/row of Rust heap, libpq holds its own `PGresult` for
/// the whole query: diesel materialises it in full before converting
/// row-by-row. That is ~600 B/row (18 fields x 16 B `PGresAttValue` + the
/// text-format field values + the per-tuple pointer array). This term is an
/// analytical estimate, NOT a measurement — measuring it needs a live
/// Postgres, and the dev cluster is off-limits for load after the incident it
/// caused. It agrees with the ~12 MiB observed at 20000 rows.
///
/// 1982 + 600 = 2582, rounded up to 2560 (2.5 KiB) for a round KiB figure.
/// At the 20000-row hard cap that is 50 MiB for one request, matching the
/// ~48 MiB measured in the incident post-mortem.
pub const TRAFFIC_ROW_COST_BYTES: u64 = 2_560;

/// Peak in-flight heap per `audit_verdicts` row, in bytes.
///
/// `AuditVerdict` is a much narrower struct than `PodTraffic` — 14 fields,
/// six of them non-string (i64, i32, NaiveDateTime) and so allocation-free,
/// against `PodTraffic`'s 18 fields of which 16 are heap strings. Scaling the
/// measured traffic figure by the string-field ratio (16 -> 8) and keeping
/// the same doubling-transient model gives ~1 KiB/row.
///
/// Not separately profiled: `clamp_audit_limit` caps this endpoint at 500
/// rows, so the worst case is 500 KiB — three orders of magnitude below the
/// traffic endpoint and not what OOMKilled the broker. It is charged anyway
/// so that a burst of audit reads cannot squeeze a traffic read out of a
/// budget it was told it had.
pub const AUDIT_ROW_COST_BYTES: u64 = 1_024;

/// Peak in-flight heap per `pod_details` row, in bytes.
///
/// Larger per row than traffic because `pod_obj` and
/// `workload_selector_labels` are `serde_json::Value` trees, each of which is
/// a `Map<String, Value>` of individually-allocated keys and values. The
/// read path runs `compact_pod_obj` (labels + `spec.hostNetwork` only), which
/// is what keeps this at kilobytes rather than the ~12 KiB/pod the full
/// manifest costs.
pub const POD_DETAIL_ROW_COST_BYTES: u64 = 4_096;

/// Assumed worst-case pod count for the reservation charged by the
/// unbounded whole-table endpoints (`/pod/info`, `/pod/list/{node}`).
///
/// These endpoints have no row limit, so their cost cannot be computed from a
/// caller-supplied `limit` the way the traffic endpoints' can. Rather than
/// adding a row cap — which would silently truncate the pod inventory the
/// advisor builds policies from — they charge a flat reservation sized from
/// this figure.
///
/// 5000 is the default max-pods-per-node (110) x a 45-node cluster, comfortably
/// above the dev cluster and above the largest cluster this has been deployed
/// to. A cluster larger than this under-charges the budget; that is accepted
/// deliberately, because these tables are bounded by cluster size (thousands
/// of rows) rather than by telemetry accumulation (millions), so the absolute
/// error stays small. The traffic tables are the ones that grow without bound
/// and they are charged exactly.
pub const ASSUMED_MAX_PODS: i64 = 5_000;

/// Assumed worst-case Service count, for `/svc/info`. Same reasoning as
/// [`ASSUMED_MAX_PODS`]; Services are far fewer than pods in every cluster
/// this has run on, so a 1:5 ratio to pods is generous.
pub const ASSUMED_MAX_SERVICES: i64 = 1_000;

/// Pods on one node, for the `/pod/list/{node}` reservation. kubelet's
/// default `--max-pods` is 110; 128 rounds it up with a little slack for
/// clusters that raise it.
pub const MAX_PODS_PER_NODE: i64 = 128;

/// Rows charged for `/pod/syscalls/{name}`. `pod_name` is that table's
/// primary key, so the query returns at most one row — but the row carries
/// the pod's whole captured syscall set as one TEXT blob. Charged as 4 rows
/// (~16 KiB) so the blob is covered rather than the row count.
pub const SYSCALL_ROWS_CHARGED: i64 = 4;

/// Peak in-flight heap per workload for `GET /seccomp/profiles`, in bytes.
///
/// READ THIS BEFORE TRUSTING THE NUMBER: it describes the list path as it
/// behaved BEFORE the `Observed::build_for_summary` change in this same
/// commit, and the post-change cost has not been measured. Deploying the
/// binary is the only way to measure it, and that had not happened when this
/// was written. So this is a deliberately retained upper bound, not a
/// description of the shipped path — which is a weaker claim than
/// [`TRAFFIC_ROW_COST_BYTES`] makes, and the difference is stated rather
/// than papered over.
///
/// What WAS measured, against the running dev cluster on 2026-09-08 — four
/// sequential unbatched calls, `kubectl top` on the broker pod between each,
/// 25s apart, 1696 workload summaries per response (1.57 MB of JSON):
///
///   baseline 352 MiB -> 366 -> 381 -> 396 -> 411     (+14, +15, +15, +15)
///
/// Linear, with nothing reclaimed between calls. Two things follow, and the
/// second one is why this constant does not carry the weight it looks like
/// it carries:
///
///   - ~15 MiB retained per call over 1696 workloads is ~9.1 KiB/workload.
///     16 KiB sits ~1.8x above that, covering the transient peak `kubectl
///     top` cannot see at its ~15s sampling cadence.
///   - Sequential calls ACCUMULATE. A budget bounds concurrent in-flight
///     cost; it does not bound monotonic retention across calls made one at
///     a time, which is what the UI's 15s poll actually produces. So this
///     reservation is NOT what fixes the OOMKill — see the note above
///     `list_seccomp_profiles`. It closes a structural gap (this module was
///     referenced only from `get.rs`, so every seccomp read was admitted
///     unconditionally) and bounds the concurrent case. The retention itself
///     is tracked separately and is not fixed here.
///
/// A workload's cost is dominated by its `workload_syscalls.syscalls` blob —
/// a comma-joined list averaging 67 names on the dev cluster, 113,995 names
/// cluster-wide. The summary emits only `syscallCount`, so those names are no
/// longer allocated on the list path, but the charge stays sized for the blob:
/// the row is still read out of libpq in full, and a workload with a mirrored
/// CR does still materialise the set for drift detection.
///
/// Re-derive from a fresh set of readings against a deployed build; do not
/// adjust it to make a reservation fit.
pub const SECCOMP_WORKLOAD_COST_BYTES: u64 = 16_384;

/// Assumed worst-case workload count for `GET /seccomp/profiles`.
///
/// Same reservation shape as [`ASSUMED_MAX_PODS`], and the same reason it
/// cannot be computed from a caller-supplied limit: the endpoint returns one
/// summary per workload ever observed and must not truncate, because the UI
/// lists it and a short list reads as "this workload has no profile" rather
/// than as an error.
///
/// 4000 is 2.4x the dev cluster's 1696 workloads. `workload_syscalls` is
/// keyed by (namespace, kind, name), so its ROW COUNT is bounded by distinct
/// workloads rather than by pod churn or telemetry volume — that half of the
/// [`ASSUMED_MAX_PODS`] argument transfers.
///
/// The other half does not, and it is the reason this constant is weaker
/// than its neighbour. A `pod_details` row is bounded in width; a
/// `workload_syscalls` row is not. `recompute_workload` unions each new
/// observation into `syscalls` and never prunes, so the per-workload cost
/// grows monotonically over a cluster's life even if no workload is ever
/// added. A flat `rows x bytes-per-row` reservation therefore decays in
/// accuracy in two independent directions at once, and past this bound the
/// two errors compound.
///
/// The better shape is to charge from a cheap aggregate — `SELECT count(*),
/// sum(length(syscalls)) FROM workload_syscalls` before the acquire — which
/// is exact, index-bounded, and would delete this constant. That is the
/// change worth making next here; it is not in this commit because the
/// commit's purpose is the allocation fix and it should not also carry a
/// query-shape change to the same handler.
pub const ASSUMED_MAX_WORKLOADS: i64 = 4_000;

/// Workload-equivalents charged for the per-workload seccomp endpoints.
///
/// `one_observed` reads a single `workload_syscalls` row, but the same
/// handlers also call `distribution_index`, which loads every
/// `seccomp_node_status.paths` JSON blob — one per node, so tens of rows on
/// the clusters this runs on rather than thousands. 64 workload-equivalents
/// (64 x 16 KiB = 1 MiB) is an ESTIMATE, not a measurement — unlike
/// [`SECCOMP_WORKLOAD_COST_BYTES`], nothing was profiled here. The dev
/// cluster has 44 nodes and `seccomp_node_status.paths` is a JSON blob of
/// unstated size per node, so "tens of rows" is reasoned from the row count
/// rather than from bytes. It covers that comfortably while staying small enough that the UI
/// opening a profile never contends with the list poll.
pub const SECCOMP_DETAIL_ROWS_CHARGED: i64 = 64;

/// Default total read budget, in MiB.
///
/// Sized from the incident: the container limit is 1 GiB (confirmed against
/// the running deployment), and the broker's resting set measured 330 MiB
/// during the post-mortem and 368 MiB a few hours later — `kubectl top` on
/// the same pod, same day. Real headroom is therefore ~656 MiB, and the
/// resting figure drifts upward as the tables grow, so the budget is sized
/// against the *larger* reading. Sizing against the smaller one is the same
/// class of optimism as the "~350 B/row" comment this change corrects.
///
/// 256 MiB takes 39% of the 656 MiB headroom, which buys:
///   - 5 concurrent hard-cap (20000-row) traffic reads at 50 MiB each, or
///   - 20 concurrent default (5000-row) reads at 12.5 MiB each, or
///   - any mix summing to 256 MiB.
///
/// and leaves ~400 MiB for the things this budget deliberately does NOT
/// govern: ingest inserts, the audit forwarder's 16 in-flight evaluations,
/// the retention and peer-resolve background passes, and allocator
/// fragmentation (freed pages are not promptly returned to the OS, so
/// steady-state RSS sits above live heap).
///
/// The real cluster-wide consumers are the advisor and mcp-server, each
/// making one such call at a time — 5 concurrent hard-cap reads is well above
/// observed demand, and smaller reads scale up proportionally, which is the
/// entire point of budgeting bytes rather than requests.
pub const DEFAULT_READ_MEMORY_BUDGET_MB: u32 = 256;

/// How long a read waits for budget before being shed, in milliseconds.
///
/// Long enough to ride out a burst — a hard-cap read holds its permit for
/// roughly 1-3s, so a queued request usually gets in — and short enough to
/// fail well inside a typical client timeout rather than hanging an actix
/// worker. Set `BROKER_READ_ACQUIRE_WAIT_MS=0` to fail fast with no queueing.
pub const DEFAULT_ACQUIRE_WAIT_MS: u64 = 5_000;

/// Fraction of a declared container memory limit the read budget may occupy.
///
/// Applied by [`ReadBudget::from_env`] when `BROKER_MEMORY_LIMIT_MB` is set
/// (wired from the chart's `resources.limits.memory`). The remaining 70% must
/// cover the measured 330 MiB resting set plus ingest, audit and
/// fragmentation. At the 1 GiB limit this clamps the budget to 307 MiB, so
/// the 256 MiB default passes untouched — the clamp exists to catch an
/// operator who raises the budget without raising the limit, which is exactly
/// how the original incident would recur.
const MAX_BUDGET_FRACTION_OF_LIMIT: f64 = 0.30;

const KIB: u64 = 1024;

/// A read was refused because the memory budget was exhausted.
///
/// Deliberately a hard error rather than a truncated result: `/pod/traffic`
/// feeds the advisor's policy generator, and a policy missing rules because
/// a read came back short is a silent security regression. A 503 is loud,
/// retryable, and visible in both logs and `broker_read_shed_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetExhausted {
    /// KiB this request asked for.
    pub requested_kib: u32,
    /// KiB the budget holds in total.
    pub total_kib: u32,
    /// How long the request waited before giving up.
    pub waited: Duration,
}

impl BudgetExhausted {
    /// Render the 503. `Retry-After: 1` because permits are released as
    /// in-flight reads finish, which is a sub-second-to-seconds timescale,
    /// not the minutes a bare 503 implies to most clients.
    pub fn into_response(self) -> HttpResponse {
        HttpResponse::ServiceUnavailable()
            .insert_header(("Retry-After", "1"))
            .body(format!(
                "broker read memory budget exhausted: this request needs {} KiB of a {} KiB \
                 budget and waited {} ms without getting it. The request was REFUSED, not \
                 truncated — retry, or lower ?limit=. Raise BROKER_READ_MEMORY_BUDGET_MB \
                 (and the container memory limit with it) if this is persistent.",
                self.requested_kib,
                self.total_kib,
                self.waited.as_millis()
            ))
    }
}

impl std::fmt::Display for BudgetExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "read budget exhausted (requested {} KiB of {} KiB, waited {} ms)",
            self.requested_kib,
            self.total_kib,
            self.waited.as_millis()
        )
    }
}

/// Estimated peak in-flight cost of a read, in KiB, rounded up.
///
/// Rounds up so a sub-KiB read still charges 1 KiB — a budget that charged 0
/// for small reads would admit unbounded numbers of them, which is the same
/// class of bug this module fixes.
///
/// Saturating throughout: `rows` arrives from a caller-supplied `?limit=`,
/// and although `clamp_*_limit` bounds it first, this must not depend on that
/// for memory safety. A negative or absurd row count yields a charge that is
/// clamped against the budget total by [`ReadBudget::acquire`] rather than
/// overflowing to a small number and slipping through.
pub fn cost_kib(rows: i64, bytes_per_row: u64) -> u32 {
    let rows = rows.max(0) as u64;
    let bytes = rows.saturating_mul(bytes_per_row);
    let kib = bytes.div_ceil(KIB).max(1);
    u32::try_from(kib).unwrap_or(u32::MAX)
}

/// Held for the lifetime of a read. Releases its share of the budget on drop.
///
/// Handlers bind this to a live local (`let _permit = ...`, never `let _ =`)
/// so it lives until the handler returns — by which point
/// `HttpResponseBuilder::json` has finished serialising and the peak has
/// passed.
#[derive(Debug)]
pub struct ReadPermit {
    _permit: OwnedSemaphorePermit,
    kib: u32,
}

impl ReadPermit {
    /// KiB this permit reserved. Exposed for logging and tests.
    pub fn kib(&self) -> u32 {
        self.kib
    }
}

/// Aggregate cap on estimated in-flight read bytes. Cheap to clone (all state
/// is shared behind `Arc`), so it can live in `web::Data`.
#[derive(Debug, Clone)]
pub struct ReadBudget {
    permits: Arc<Semaphore>,
    total_kib: u32,
    shed: Arc<AtomicU64>,
    wait: Duration,
}

impl ReadBudget {
    /// Construct with an explicit budget. `total_kib` is floored at 1 so a
    /// misconfigured 0 cannot deadlock every read forever (the same
    /// floor-to-1 defense `audit_inflight_permits` applies to its own
    /// semaphore).
    pub fn with_budget_kib(total_kib: u32, wait: Duration) -> Self {
        let total_kib = total_kib.max(1);
        Self {
            permits: Arc::new(Semaphore::new(total_kib as usize)),
            total_kib,
            shed: Arc::new(AtomicU64::new(0)),
            wait,
        }
    }

    /// Build from the environment, applying the coherence clamp.
    ///
    /// - `BROKER_READ_MEMORY_BUDGET_MB` — total budget, default
    ///   [`DEFAULT_READ_MEMORY_BUDGET_MB`].
    /// - `BROKER_READ_ACQUIRE_WAIT_MS` — queue-before-shed window, default
    ///   [`DEFAULT_ACQUIRE_WAIT_MS`]. `0` means fail fast.
    /// - `BROKER_MEMORY_LIMIT_MB` — the container's memory limit, if the
    ///   chart passes it. When set, the budget is clamped to
    ///   [`MAX_BUDGET_FRACTION_OF_LIMIT`] of it.
    ///
    /// Clamping rather than refusing to start is deliberate. An incoherent
    /// budget is a real bug and it warns loudly, but a broker that
    /// crash-loops on a bad env var takes the whole telemetry pipeline down,
    /// whereas a clamped one keeps serving inside a safe bound. The warn is
    /// what an operator acts on; the clamp is what keeps them safe until they
    /// do.
    pub fn from_env() -> Self {
        let configured_mb = std::env::var("BROKER_READ_MEMORY_BUDGET_MB")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .map(|n| n.max(1))
            .unwrap_or(DEFAULT_READ_MEMORY_BUDGET_MB);

        let wait_ms = std::env::var("BROKER_READ_ACQUIRE_WAIT_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_ACQUIRE_WAIT_MS);

        let limit_mb = std::env::var("BROKER_MEMORY_LIMIT_MB")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .filter(|n| *n > 0);

        let effective_mb = clamp_budget_to_limit(configured_mb, limit_mb);
        if effective_mb != configured_mb {
            warn!(
                configured_mb,
                limit_mb = limit_mb.unwrap_or(0),
                effective_mb,
                max_fraction = MAX_BUDGET_FRACTION_OF_LIMIT,
                "BROKER_READ_MEMORY_BUDGET_MB exceeds a safe fraction of BROKER_MEMORY_LIMIT_MB; \
                 clamping. A budget larger than the container can hold is how the broker gets \
                 OOMKilled under concurrent reads — raise the container memory limit to use a \
                 larger budget."
            );
        }

        info!(
            budget_mb = effective_mb,
            acquire_wait_ms = wait_ms,
            traffic_row_cost_bytes = TRAFFIC_ROW_COST_BYTES,
            "read memory budget active"
        );

        Self::with_budget_kib(
            effective_mb.saturating_mul(1024),
            Duration::from_millis(wait_ms),
        )
    }

    /// Reserve `cost_kib` of budget, waiting up to the configured window.
    ///
    /// The charge is clamped to the budget total. Without that clamp a
    /// request estimated above the total would wait forever —
    /// `Semaphore::acquire_many` can never succeed for more permits than the
    /// semaphore was built with — turning "budget too small" into a hung
    /// request instead of a served one. Clamped, an oversized read simply runs
    /// alone with the whole budget to itself, which is the correct
    /// degradation: it still completes, and nothing runs beside it.
    pub async fn acquire(&self, cost_kib: u32) -> Result<ReadPermit, BudgetExhausted> {
        let charge = cost_kib.clamp(1, self.total_kib);

        let acquired = if self.wait.is_zero() {
            // Fail-fast path. try_acquire_many avoids arming a timer at all.
            self.permits.clone().try_acquire_many_owned(charge).ok()
        } else {
            tokio::time::timeout(self.wait, self.permits.clone().acquire_many_owned(charge))
                .await
                .ok()
                .and_then(Result::ok)
        };

        match acquired {
            Some(permit) => Ok(ReadPermit {
                _permit: permit,
                kib: charge,
            }),
            None => {
                self.shed.fetch_add(1, Ordering::Relaxed);
                let err = BudgetExhausted {
                    requested_kib: charge,
                    total_kib: self.total_kib,
                    waited: self.wait,
                };
                warn!(
                    requested_kib = charge,
                    total_kib = self.total_kib,
                    waited_ms = self.wait.as_millis() as u64,
                    "read shed: memory budget exhausted; request refused (NOT truncated)"
                );
                Err(err)
            }
        }
    }

    /// Free budget, in KiB. Surfaced as `broker_read_budget_kib_available`;
    /// pegged near 0 means reads are queueing on memory.
    pub fn available_kib(&self) -> u32 {
        u32::try_from(self.permits.available_permits()).unwrap_or(u32::MAX)
    }

    /// Total budget, in KiB. Surfaced as `broker_read_budget_kib_total`.
    pub fn total_kib(&self) -> u32 {
        self.total_kib
    }

    /// Reads refused for lack of budget. Surfaced as
    /// `broker_read_shed_total`; any sustained increase means the budget or
    /// the memory limit is too small for the offered load.
    pub fn shed_count(&self) -> u64 {
        self.shed.load(Ordering::Relaxed)
    }
}

/// Clamp a configured budget against a declared container memory limit.
///
/// Pure and separately testable so the guard cannot silently regress — the
/// same reason `pool_size_with_headroom` is split out of the pool builder in
/// `main.rs`. Returns `configured` unchanged when no limit is declared: with
/// no limit to reason about, the operator's number is the best information
/// available.
pub fn clamp_budget_to_limit(configured_mb: u32, limit_mb: Option<u32>) -> u32 {
    match limit_mb {
        Some(limit) => {
            let ceiling = (f64::from(limit) * MAX_BUDGET_FRACTION_OF_LIMIT) as u32;
            configured_mb.min(ceiling.max(1))
        }
        None => configured_mb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(kib: u32) -> ReadBudget {
        ReadBudget::with_budget_kib(kib, Duration::from_millis(0))
    }

    // ---- cost_kib ----------------------------------------------------

    #[test]
    fn cost_rounds_up_to_whole_kib() {
        // 3 rows x 2560 B = 7680 B = 7.5 KiB -> 8 KiB. Rounding down would
        // let the budget admit more bytes than it holds.
        assert_eq!(cost_kib(3, TRAFFIC_ROW_COST_BYTES), 8);
    }

    #[test]
    fn cost_of_zero_rows_still_charges_one_kib() {
        // A zero charge would admit unbounded concurrent requests — the same
        // class of unbounded-concurrency bug this module fixes.
        assert_eq!(cost_kib(0, TRAFFIC_ROW_COST_BYTES), 1);
        assert_eq!(cost_kib(-5, TRAFFIC_ROW_COST_BYTES), 1);
        assert_eq!(cost_kib(i64::MIN, TRAFFIC_ROW_COST_BYTES), 1);
    }

    #[test]
    fn cost_of_hard_cap_traffic_read_matches_the_measurement() {
        // The number the whole design rests on: one hard-cap /pod/traffic
        // read is ~50 MiB. If this assertion ever moves, the incident
        // arithmetic in the module docs is stale.
        let kib = cost_kib(20_000, TRAFFIC_ROW_COST_BYTES);
        assert_eq!(kib, 50_000, "20000 rows x 2560 B = 50000 KiB");
        assert!(
            (48..=52).contains(&(kib / 1024)),
            "hard-cap read should be ~48-52 MiB, got {} MiB",
            kib / 1024
        );
    }

    #[test]
    fn cost_saturates_instead_of_overflowing() {
        // i64::MAX rows x 2560 B overflows u64 many times over. Wrapping
        // would produce a tiny charge that sails through the budget — the
        // exact failure mode a memory bound must not have.
        assert_eq!(cost_kib(i64::MAX, TRAFFIC_ROW_COST_BYTES), u32::MAX);
    }

    // ---- acquire / release -------------------------------------------

    #[tokio::test]
    async fn permit_reserves_and_releases_budget() {
        let b = budget(100);
        assert_eq!(b.available_kib(), 100);
        {
            let p = b.acquire(40).await.expect("fits");
            assert_eq!(p.kib(), 40);
            assert_eq!(b.available_kib(), 60);
        }
        assert_eq!(b.available_kib(), 100, "permit must release on drop");
    }

    #[tokio::test]
    async fn concurrent_reads_are_bounded_by_bytes_not_count() {
        // The core property. A 100 KiB budget admits two 50 KiB reads and
        // refuses the third — regardless of how many pool connections or
        // actix workers are free.
        let b = budget(100);
        let _a = b.acquire(50).await.expect("first fits");
        let _c = b.acquire(50).await.expect("second fits exactly");
        assert_eq!(b.available_kib(), 0);
        let third = b.acquire(50).await;
        assert!(third.is_err(), "third must be shed, not queued forever");
        assert_eq!(b.shed_count(), 1);
    }

    #[tokio::test]
    async fn small_reads_get_more_concurrency_than_large_ones() {
        // Why the unit is bytes: the same budget that admits 2 hard-cap
        // reads admits 20 default-sized ones.
        let b = budget(100);
        let mut held = Vec::new();
        for _ in 0..20 {
            held.push(b.acquire(5).await.expect("5 KiB read fits"));
        }
        assert_eq!(b.available_kib(), 0);
        assert!(b.acquire(5).await.is_err(), "21st must shed");
    }

    // ---- the boundary that would otherwise deadlock -------------------

    #[tokio::test]
    async fn read_larger_than_whole_budget_runs_alone_instead_of_hanging() {
        // tokio's acquire_many can NEVER succeed for more permits than the
        // semaphore holds. Without the clamp in acquire(), a request
        // estimated above the total would wait forever — a hung request
        // instead of a served one, and an actix worker pinned with it.
        let b = budget(10);
        let p = b.acquire(9_999).await.expect("must not hang; runs alone");
        assert_eq!(p.kib(), 10, "charge is clamped to the whole budget");
        assert_eq!(b.available_kib(), 0);

        // and it really does exclude everything else while it runs
        assert!(b.acquire(1).await.is_err());
        drop(p);
        assert_eq!(b.available_kib(), 10);
    }

    #[tokio::test]
    async fn budget_of_zero_is_floored_not_deadlocked() {
        // A misconfigured BROKER_READ_MEMORY_BUDGET_MB=0 must not wedge
        // every read forever.
        let b = ReadBudget::with_budget_kib(0, Duration::from_millis(0));
        assert_eq!(b.total_kib(), 1);
        let p = b.acquire(4_096).await.expect("still serves, serially");
        assert_eq!(p.kib(), 1);
    }

    // ---- the shed path ------------------------------------------------

    #[tokio::test]
    async fn shed_is_counted_and_reported_as_503_not_an_empty_result() {
        let b = budget(10);
        let _held = b.acquire(10).await.expect("fills the budget");

        let err = b.acquire(10).await.expect_err("must shed");
        assert_eq!(b.shed_count(), 1);
        assert_eq!(err.requested_kib, 10);
        assert_eq!(err.total_kib, 10);

        let resp = err.into_response();
        assert_eq!(
            resp.status(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            resp.headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok()),
            Some("1"),
            "clients need to know this is retryable in ~seconds"
        );
    }

    #[tokio::test]
    async fn shed_message_says_refused_not_truncated() {
        // The contract that protects policy completeness: an operator or a
        // client author reading this message must not mistake it for a
        // partial result.
        let err = BudgetExhausted {
            requested_kib: 50_000,
            total_kib: 262_144,
            waited: Duration::from_millis(5_000),
        };
        let msg = format!("{err}");
        assert!(msg.contains("50000"), "must name the request's cost");
        assert!(msg.contains("262144"), "must name the budget");
    }

    #[tokio::test]
    async fn waiting_read_is_admitted_when_a_permit_frees() {
        // The queue must actually work — a burst should ride out, not shed
        // on the first collision.
        let b = ReadBudget::with_budget_kib(10, Duration::from_millis(2_000));
        let held = b.acquire(10).await.expect("fills the budget");
        let b2 = b.clone();
        let waiter = tokio::spawn(async move { b2.acquire(10).await.map(|p| p.kib()) });

        // Release after a beat; the queued acquire should then complete.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(held);

        let got = waiter
            .await
            .expect("task joins")
            .expect("admitted, not shed");
        assert_eq!(got, 10);
        assert_eq!(
            b.shed_count(),
            0,
            "a ridden-out burst must not count as shed"
        );
    }

    #[tokio::test]
    async fn zero_wait_fails_fast_without_queueing() {
        let b = ReadBudget::with_budget_kib(10, Duration::from_millis(0));
        let _held = b.acquire(10).await.expect("fills the budget");
        let start = std::time::Instant::now();
        assert!(b.acquire(1).await.is_err());
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "zero wait must not queue"
        );
    }

    // ---- the coherence clamp ------------------------------------------

    #[test]
    fn budget_is_clamped_to_a_fraction_of_a_declared_memory_limit() {
        // 1 GiB limit -> 307 MiB ceiling. The 256 MiB default passes.
        assert_eq!(clamp_budget_to_limit(256, Some(1024)), 256);
        // An operator raising the budget without raising the limit gets
        // clamped rather than an OOMKill under load.
        assert_eq!(clamp_budget_to_limit(900, Some(1024)), 307);
        assert_eq!(clamp_budget_to_limit(4_096, Some(512)), 153);
    }

    #[test]
    fn budget_is_untouched_when_no_limit_is_declared() {
        assert_eq!(clamp_budget_to_limit(256, None), 256);
        assert_eq!(clamp_budget_to_limit(8_192, None), 8_192);
    }

    #[test]
    fn clamp_never_yields_zero() {
        // A tiny declared limit must still leave a servable budget rather
        // than a 0 MiB one.
        assert_eq!(clamp_budget_to_limit(256, Some(1)), 1);
    }

    // ---- the arithmetic from the incident ------------------------------

    #[test]
    fn default_budget_admits_fewer_heavy_reads_than_the_pool_allows() {
        // This is the whole bug in one assertion. The pool permits 32
        // concurrent heavy reads; memory permits far fewer. Before this
        // module, nothing enforced the smaller number.
        let hard_cap_read_kib = cost_kib(20_000, TRAFFIC_ROW_COST_BYTES);
        let budget_kib = DEFAULT_READ_MEMORY_BUDGET_MB * 1024;
        let concurrent_heavy_reads = budget_kib / hard_cap_read_kib;

        assert!(
            concurrent_heavy_reads < 32,
            "the budget must bind before the pool does, else it changes nothing: \
             {concurrent_heavy_reads} allowed vs pool's 32"
        );
        assert_eq!(concurrent_heavy_reads, 5);

        // And the aggregate must fit the measured headroom, using the
        // CONSERVATIVE reading: 1 GiB limit minus the larger 368 MiB
        // resting set = ~656 MiB.
        let worst_case_mb = (concurrent_heavy_reads * hard_cap_read_kib) / 1024;
        assert!(
            worst_case_mb < 656,
            "worst-case concurrent read heap {worst_case_mb} MiB must fit \
             the 656 MiB of measured headroom"
        );
    }

    /// The seccomp list reservation is the one that OOMKilled the broker, so
    /// its sizing needs the same guard the traffic read has: big enough to
    /// bind, small enough that a normal UI poll is not competing with the
    /// whole budget.
    #[test]
    fn seccomp_list_reservation_binds_without_monopolising_the_budget() {
        let seccomp_kib = cost_kib(ASSUMED_MAX_WORKLOADS, SECCOMP_WORKLOAD_COST_BYTES);
        let budget_kib = DEFAULT_READ_MEMORY_BUDGET_MB * 1024;
        let concurrent = budget_kib / seccomp_kib;

        // A RANGE, not an equality. The requirement is "binds well before the
        // 64 actix workers, without monopolising the budget" — not one exact
        // number. An equality here would fail the moment anyone follows the
        // instruction three lines above SECCOMP_WORKLOAD_COST_BYTES to
        // re-derive it against a deployed build, i.e. this test would break
        // when a maintainer does the right thing.
        assert!(
            (2..=8).contains(&concurrent),
            "expected 2-8 concurrent seccomp list reads, got {concurrent}: \
             below 2 a single UI poll monopolises the budget, above 8 it no \
             longer binds meaningfully before the worker count does"
        );

        // But one call must not eat the whole budget, or a single UI poll
        // would shed every concurrent traffic read and the fix would trade
        // one outage for another.
        let hard_cap_read_kib = cost_kib(20_000, TRAFFIC_ROW_COST_BYTES);
        assert!(
            seccomp_kib + hard_cap_read_kib <= budget_kib,
            "one seccomp list read ({seccomp_kib} KiB) plus one hard-cap traffic \
             read ({hard_cap_read_kib} KiB) must both fit the {budget_kib} KiB budget"
        );

        // And the reservation must actually exceed what was measured on the
        // dev cluster (1696 workloads), or it would under-charge the very
        // call that caused the incident.
        let measured_kib = cost_kib(1_696, SECCOMP_WORKLOAD_COST_BYTES);
        assert!(
            seccomp_kib > measured_kib,
            "the flat reservation {seccomp_kib} KiB must cover the observed \
             1696-workload cluster ({measured_kib} KiB)"
        );
    }

    #[test]
    fn pre_fix_configuration_would_have_exceeded_the_container_limit() {
        // Pins the regression: 32 concurrent hard-cap reads (what
        // DB_POOL_MAX_SIZE alone permitted) against a 1 GiB limit.
        let hard_cap_read_mb = cost_kib(20_000, TRAFFIC_ROW_COST_BYTES) / 1024;
        let unbounded_worst_case_mb = 32 * hard_cap_read_mb;
        let resting_mb = 330;
        let limit_mb = 1024;
        assert!(
            unbounded_worst_case_mb + resting_mb > limit_mb,
            "the pre-fix worst case must exceed the limit — that is the OOMKill"
        );
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    /// Panic-safe env isolation, same contract as the guard in `conn.rs`:
    /// callers must hold `crate::test_support::env_lock()` for the guard's
    /// lifetime, because `std::env` is process-global and parallel tests
    /// mutating even different keys race on libc's `environ`.
    struct EnvGuard {
        key: String,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &str, value: Option<&str>) -> Self {
            let prev = std::env::var(key).ok();
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
            Self {
                key: key.to_string(),
                prev,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }

    /// Clear all three knobs, then apply `set`, then build. Returns the
    /// budget's resolved total in KiB.
    fn budget_kib_with(set: &[(&str, &str)]) -> u32 {
        let _lock = crate::test_support::env_lock();
        let _g1 = EnvGuard::set("BROKER_READ_MEMORY_BUDGET_MB", None);
        let _g2 = EnvGuard::set("BROKER_READ_ACQUIRE_WAIT_MS", None);
        let _g3 = EnvGuard::set("BROKER_MEMORY_LIMIT_MB", None);
        let _applied: Vec<EnvGuard> = set.iter().map(|(k, v)| EnvGuard::set(k, Some(v))).collect();
        ReadBudget::from_env().total_kib()
    }

    #[test]
    fn defaults_to_the_documented_budget_when_unset() {
        assert_eq!(budget_kib_with(&[]), DEFAULT_READ_MEMORY_BUDGET_MB * 1024);
    }

    #[test]
    fn honours_an_explicit_budget() {
        assert_eq!(
            budget_kib_with(&[("BROKER_READ_MEMORY_BUDGET_MB", "64")]),
            64 * 1024
        );
    }

    #[test]
    fn trims_whitespace_around_values() {
        // Same env-trim defense as every other reader in the broker: a
        // pasted "  64\n" from a values.yaml block scalar must not fall back
        // to the default silently.
        assert_eq!(
            budget_kib_with(&[("BROKER_READ_MEMORY_BUDGET_MB", "  64\n")]),
            64 * 1024
        );
    }

    #[test]
    fn garbage_falls_back_to_the_default() {
        assert_eq!(
            budget_kib_with(&[("BROKER_READ_MEMORY_BUDGET_MB", "not-a-number")]),
            DEFAULT_READ_MEMORY_BUDGET_MB * 1024
        );
    }

    #[test]
    fn zero_is_floored_to_one_mb_not_deadlocked() {
        // A 0 MiB budget would refuse or hang every read forever. Floor it,
        // matching db_pool_max_size's floor-to-1.
        assert_eq!(
            budget_kib_with(&[("BROKER_READ_MEMORY_BUDGET_MB", "0")]),
            1024
        );
    }

    #[test]
    fn a_declared_container_limit_clamps_an_oversized_budget() {
        // The coherence check that would have caught the original
        // misconfiguration: asking for 900 MiB of reads inside a 1 GiB
        // container is exactly how the broker got OOMKilled.
        assert_eq!(
            budget_kib_with(&[
                ("BROKER_READ_MEMORY_BUDGET_MB", "900"),
                ("BROKER_MEMORY_LIMIT_MB", "1024"),
            ]),
            307 * 1024
        );
    }

    #[test]
    fn a_coherent_budget_passes_the_limit_check_untouched() {
        // The shipped default inside the shipped limit must not be clamped —
        // if it were, the default would be a lie.
        assert_eq!(
            budget_kib_with(&[
                (
                    "BROKER_READ_MEMORY_BUDGET_MB",
                    &DEFAULT_READ_MEMORY_BUDGET_MB.to_string()
                ),
                ("BROKER_MEMORY_LIMIT_MB", "1024"),
            ]),
            DEFAULT_READ_MEMORY_BUDGET_MB * 1024
        );
    }

    #[test]
    fn an_unparseable_memory_limit_is_ignored_rather_than_clamping_to_nothing() {
        // A malformed BROKER_MEMORY_LIMIT_MB must not collapse the budget to
        // 1 MiB and throttle the broker to a crawl.
        assert_eq!(
            budget_kib_with(&[
                ("BROKER_READ_MEMORY_BUDGET_MB", "128"),
                ("BROKER_MEMORY_LIMIT_MB", "1Gi"),
            ]),
            128 * 1024
        );
    }
}
