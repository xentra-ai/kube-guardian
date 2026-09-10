//! Wire and row types for the compute-contention feature
//! (docs/design/compute-contention-monitoring.md, "Data model").
//!
//! Three families live here, kept apart on purpose:
//!
//! 1. **Ingest envelopes** (`ComputeBatch`, `ComputeHistoryBatch` and
//!    their nested sample structs) — exactly the JSON the controller
//!    POSTs. Field names are the contract; nothing here is renamed on
//!    the way in. All `cpu.*` / `memory.*` counters are DELTAS over
//!    `interval_ms`, gauges are instantaneous (or avg/max/last objects
//!    on the minute envelope).
//! 2. **Rows** for the four tables — positional `Queryable` structs that
//!    must match `schema.rs` column-for-column. The history and
//!    contention tables have a BIGSERIAL id, so each has a separate
//!    `New*` Insertable without it.
//! 3. **`Finding`** — what `GET /compute/findings` returns, computed by
//!    `compute.rs` and shared by the UI, the CLI and the assistant.

use chrono::{DateTime, NaiveDateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------
// Ingest: POST /pod/compute/batch
// ---------------------------------------------------------------------

/// One node's sample: node-level state plus a sample per container.
#[derive(Debug, Clone, Deserialize)]
pub struct ComputeBatch {
    pub node: String,
    /// RFC3339 UTC.
    pub ts: DateTime<Utc>,
    pub interval_ms: i64,
    #[serde(default)]
    pub ctxt_per_sec: f64,
    #[serde(default = "default_true")]
    pub compute_enabled: bool,
    #[serde(default = "default_true")]
    pub compute_supported: bool,
    #[serde(default)]
    pub contention_loaded: bool,
    #[serde(default)]
    pub node_pressure: NodePressure,
    #[serde(default)]
    pub node_capacity: NodeCapacity,
    #[serde(default)]
    pub bpf_occupancy: BpfOccupancy,
    #[serde(default)]
    pub unknown_blame_share: f64,
    #[serde(default)]
    pub containers: Vec<ComputeContainerSample>,
}

fn default_true() -> bool {
    true
}

/// `/proc/pressure/{cpu,memory}` some/full avg10, percent.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NodePressure {
    #[serde(default)]
    pub cpu_some10: f64,
    #[serde(default)]
    pub cpu_full10: f64,
    #[serde(default)]
    pub mem_some10: f64,
    #[serde(default)]
    pub mem_full10: f64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NodeCapacity {
    #[serde(default)]
    pub cpu_cores: i32,
    #[serde(default)]
    pub memory_bytes: i64,
}

/// Occupancy of the scheduler probe's BPF maps. A leak shows up here as
/// a number that never returns to baseline.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BpfOccupancy {
    #[serde(default)]
    pub runq_enqueued: i64,
    #[serde(default)]
    pub runq_hist: i64,
    #[serde(default)]
    pub pair: i64,
}

/// One container's 5 s sample.
#[derive(Debug, Clone, Deserialize)]
pub struct ComputeContainerSample {
    /// `<pod_uid>/<container>` — the primary key of `pod_compute_latest`.
    pub container_uid: String,
    pub pod_uid: String,
    pub pod_name: String,
    pub namespace: String,
    pub container: String,
    /// 64-bit kernfs id; the upper half carries generation bits, so it
    /// is accepted unsigned and stored as the same bit pattern in a
    /// BIGINT (see `cgroup_id_to_db`).
    #[serde(default)]
    pub cgroup_id: u64,
    pub cpu: CpuSample,
    pub memory: MemorySample,
    /// `null` when the scheduler probe is not loaded on the node.
    #[serde(default)]
    pub runq: Option<RunqSample>,
    #[serde(default)]
    pub blame: Vec<BlameEntry>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CpuSample {
    #[serde(default)]
    pub usage_usec: i64,
    /// `null` when the container has no CPU limit (`cpu.max` = max).
    #[serde(default)]
    pub quota_usec: Option<i64>,
    #[serde(default = "default_period_usec")]
    pub period_usec: i64,
    #[serde(default)]
    pub request_millis: Option<i64>,
    #[serde(default)]
    pub limit_millis: Option<i64>,
    #[serde(default)]
    pub nr_periods: i64,
    #[serde(default)]
    pub nr_throttled: i64,
    #[serde(default)]
    pub throttled_usec: i64,
    #[serde(default)]
    pub psi_some10: f64,
    #[serde(default)]
    pub psi_full10: f64,
}

/// CFS default period; what `cpu.max` reports when no quota is set.
fn default_period_usec() -> i64 {
    100_000
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MemorySample {
    #[serde(default)]
    pub current: i64,
    #[serde(default)]
    pub working_set: i64,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub request: Option<i64>,
    #[serde(default)]
    pub psi_some10: f64,
    #[serde(default)]
    pub psi_full10: f64,
    #[serde(default)]
    pub events_high: i64,
    #[serde(default)]
    pub events_max: i64,
    #[serde(default)]
    pub oom_kill: i64,
    #[serde(default)]
    pub refault: i64,
    #[serde(default)]
    pub pgmajfault: i64,
}

/// Run-queue latency summary for the interval. `hist` is the raw
/// 24-bucket delta (bucket b = [2^b, 2^(b+1)) µs, bucket 23 = overflow).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RunqSample {
    #[serde(default)]
    pub count: i64,
    #[serde(default)]
    pub p50_us: i64,
    #[serde(default)]
    pub p95_us: i64,
    #[serde(default)]
    pub p99_us: i64,
    #[serde(default)]
    pub max_us: i64,
    #[serde(default)]
    pub overflow: i64,
    #[serde(default)]
    pub hist: Vec<i64>,
}

/// One culprit on a victim's blame list. `kind` is one of `pod`,
/// `system`, `kernel`, `unknown` (see "Culprit resolution in userspace"
/// in the design); `ref` is the human-readable identity for that kind;
/// `container_uid` is set only for tracked pod culprits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameEntry {
    #[serde(default)]
    pub cgroup_id: u64,
    pub kind: String,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default)]
    pub container_uid: Option<String>,
    #[serde(default)]
    pub count: i64,
    #[serde(default)]
    pub wait_ns: i64,
}

// ---------------------------------------------------------------------
// Ingest: POST /pod/compute/history/batch
// ---------------------------------------------------------------------

/// The minute envelope. Same node-level shape as `ComputeBatch` (extra
/// node fields are accepted and ignored); containers carry summed
/// counters and avg/max/last gauges.
#[derive(Debug, Clone, Deserialize)]
pub struct ComputeHistoryBatch {
    pub node: String,
    pub ts: DateTime<Utc>,
    #[serde(default = "default_history_interval_ms")]
    pub interval_ms: i64,
    #[serde(default = "default_resolution_secs")]
    pub resolution_secs: i32,
    #[serde(default)]
    pub containers: Vec<ComputeHistoryContainer>,
}

fn default_history_interval_ms() -> i64 {
    60_000
}

fn default_resolution_secs() -> i32 {
    60
}

/// A gauge folded over the minute: average, maximum and the last
/// sample's value.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
pub struct Gauge {
    #[serde(default)]
    pub avg: f64,
    #[serde(default)]
    pub max: f64,
    #[serde(default)]
    pub last: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComputeHistoryContainer {
    pub container_uid: String,
    pub pod_uid: String,
    pub pod_name: String,
    pub namespace: String,
    pub container: String,
    #[serde(default)]
    pub cgroup_id: u64,
    pub cpu: CpuHistory,
    pub memory: MemoryHistory,
    #[serde(default)]
    pub runq: Option<RunqSample>,
    /// Top pairs by `wait_ns` over the minute.
    #[serde(default)]
    pub blame: Vec<BlameEntry>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CpuHistory {
    /// Derived by the controller: usage_usec / interval → millicores.
    #[serde(default)]
    pub usage_millis: Gauge,
    #[serde(default)]
    pub quota_usec: Option<i64>,
    #[serde(default = "default_period_usec")]
    pub period_usec: i64,
    #[serde(default)]
    pub request_millis: Option<i64>,
    #[serde(default)]
    pub limit_millis: Option<i64>,
    #[serde(default)]
    pub nr_periods: i64,
    #[serde(default)]
    pub nr_throttled: i64,
    #[serde(default)]
    pub throttled_usec: i64,
    #[serde(default)]
    pub psi_some10: Gauge,
    #[serde(default)]
    pub psi_full10: Gauge,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MemoryHistory {
    #[serde(default)]
    pub current: Gauge,
    #[serde(default)]
    pub working_set: Gauge,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub request: Option<i64>,
    #[serde(default)]
    pub psi_some10: Gauge,
    #[serde(default)]
    pub psi_full10: Gauge,
    #[serde(default)]
    pub events_high: i64,
    #[serde(default)]
    pub events_max: i64,
    #[serde(default)]
    pub oom_kill: i64,
    #[serde(default)]
    pub refault: i64,
    #[serde(default)]
    pub pgmajfault: i64,
}

/// Broker reply to both ingest endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Accepted {
    pub accepted: usize,
}

// ---------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------

/// Store a kernfs cgroup id as the same 64-bit pattern in a BIGINT.
/// Ids with the generation high bit set would otherwise fail to
/// convert; readers that need the unsigned value cast back.
pub fn cgroup_id_to_db(id: u64) -> i64 {
    id as i64
}

/// `usage_usec` over `interval_ms` expressed in millicores: one full
/// core for the whole interval is `interval_ms * 1000` µs, i.e. 1000 m.
/// So millicores = usage_usec / interval_ms. Guarded against a zero or
/// negative interval (a malformed batch must not produce inf/NaN in a
/// DOUBLE column that the UI then renders).
pub fn usage_millis(usage_usec: i64, interval_ms: i64) -> f64 {
    if interval_ms <= 0 {
        return 0.0;
    }
    usage_usec as f64 / interval_ms as f64
}

/// One live container row. Positional — matches
/// `schema::pod_compute_latest` exactly. `treat_none_as_null` so an
/// upsert that removes a limit (quota went from a value to `null`)
/// actually writes the NULL instead of keeping the stale value.
#[derive(
    Debug, Clone, Serialize, Deserialize, Queryable, Insertable, AsChangeset, Identifiable,
)]
#[diesel(table_name = crate::schema::pod_compute_latest)]
#[diesel(primary_key(container_uid))]
#[diesel(treat_none_as_null = true)]
pub struct PodComputeLatest {
    pub container_uid: String,
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub container: String,
    pub node: String,
    pub cgroup_id: i64,
    pub ts: NaiveDateTime,
    pub interval_ms: i32,
    pub cpu_usage_millis: f64,
    pub cpu_quota_usec: Option<i64>,
    pub cpu_period_usec: i64,
    pub cpu_request_millis: Option<i64>,
    pub cpu_limit_millis: Option<i64>,
    pub cpu_nr_periods: i64,
    pub cpu_nr_throttled: i64,
    pub cpu_throttled_usec: i64,
    pub cpu_psi_some10: f64,
    pub cpu_psi_full10: f64,
    pub mem_current: i64,
    pub mem_working_set: i64,
    pub mem_limit: Option<i64>,
    pub mem_request: Option<i64>,
    pub mem_psi_some10: f64,
    pub mem_psi_full10: f64,
    pub mem_events_high: i64,
    pub mem_events_max: i64,
    pub mem_oom_kill: i64,
    pub mem_refault: i64,
    pub mem_pgmajfault: i64,
    pub runq_count: Option<i64>,
    pub runq_p50_us: Option<i64>,
    pub runq_p95_us: Option<i64>,
    pub runq_p99_us: Option<i64>,
    pub runq_max_us: Option<i64>,
    pub runq_overflow: Option<i64>,
    /// The wire `blame` array, verbatim.
    pub blame: serde_json::Value,
    pub updated_at: NaiveDateTime,
}

impl PodComputeLatest {
    /// Flatten one wire sample into a row. `now` is stamped as
    /// `updated_at` (arrival time, what the dead-container prune keys on)
    /// while `ts` stays the controller's sample time.
    pub fn from_sample(
        batch: &ComputeBatch,
        c: &ComputeContainerSample,
        now: NaiveDateTime,
    ) -> Self {
        let interval_ms = i32::try_from(batch.interval_ms).unwrap_or(i32::MAX);
        let runq = c.runq.as_ref();
        PodComputeLatest {
            container_uid: c.container_uid.clone(),
            pod_uid: c.pod_uid.clone(),
            namespace: c.namespace.clone(),
            pod_name: c.pod_name.clone(),
            container: c.container.clone(),
            node: batch.node.clone(),
            cgroup_id: cgroup_id_to_db(c.cgroup_id),
            ts: batch.ts.naive_utc(),
            interval_ms,
            cpu_usage_millis: usage_millis(c.cpu.usage_usec, batch.interval_ms),
            cpu_quota_usec: c.cpu.quota_usec,
            cpu_period_usec: c.cpu.period_usec,
            cpu_request_millis: c.cpu.request_millis,
            cpu_limit_millis: c.cpu.limit_millis,
            cpu_nr_periods: c.cpu.nr_periods,
            cpu_nr_throttled: c.cpu.nr_throttled,
            cpu_throttled_usec: c.cpu.throttled_usec,
            cpu_psi_some10: c.cpu.psi_some10,
            cpu_psi_full10: c.cpu.psi_full10,
            mem_current: c.memory.current,
            mem_working_set: c.memory.working_set,
            mem_limit: c.memory.limit,
            mem_request: c.memory.request,
            mem_psi_some10: c.memory.psi_some10,
            mem_psi_full10: c.memory.psi_full10,
            mem_events_high: c.memory.events_high,
            mem_events_max: c.memory.events_max,
            mem_oom_kill: c.memory.oom_kill,
            mem_refault: c.memory.refault,
            mem_pgmajfault: c.memory.pgmajfault,
            runq_count: runq.map(|r| r.count),
            runq_p50_us: runq.map(|r| r.p50_us),
            runq_p95_us: runq.map(|r| r.p95_us),
            runq_p99_us: runq.map(|r| r.p99_us),
            runq_max_us: runq.map(|r| r.max_us),
            runq_overflow: runq.map(|r| r.overflow),
            blame: serde_json::to_value(&c.blame).unwrap_or(serde_json::Value::Array(vec![])),
            updated_at: now,
        }
    }
}

/// One node's live compute state. Positional — matches
/// `schema::node_compute_latest`.
#[derive(
    Debug, Clone, Serialize, Deserialize, Queryable, Insertable, AsChangeset, Identifiable,
)]
#[diesel(table_name = crate::schema::node_compute_latest)]
#[diesel(primary_key(node))]
pub struct NodeComputeLatest {
    pub node: String,
    pub ts: NaiveDateTime,
    pub interval_ms: i32,
    pub ctxt_per_sec: f64,
    pub compute_enabled: bool,
    pub compute_supported: bool,
    pub contention_loaded: bool,
    pub cpu_some10: f64,
    pub cpu_full10: f64,
    pub mem_some10: f64,
    pub mem_full10: f64,
    pub cpu_cores: i32,
    pub memory_bytes: i64,
    pub bpf_runq_enqueued: i64,
    pub bpf_runq_hist: i64,
    pub bpf_pair: i64,
    pub unknown_blame_share: f64,
    pub updated_at: NaiveDateTime,
}

impl NodeComputeLatest {
    pub fn from_batch(batch: &ComputeBatch, now: NaiveDateTime) -> Self {
        NodeComputeLatest {
            node: batch.node.clone(),
            ts: batch.ts.naive_utc(),
            interval_ms: i32::try_from(batch.interval_ms).unwrap_or(i32::MAX),
            ctxt_per_sec: batch.ctxt_per_sec,
            compute_enabled: batch.compute_enabled,
            compute_supported: batch.compute_supported,
            contention_loaded: batch.contention_loaded,
            cpu_some10: batch.node_pressure.cpu_some10,
            cpu_full10: batch.node_pressure.cpu_full10,
            mem_some10: batch.node_pressure.mem_some10,
            mem_full10: batch.node_pressure.mem_full10,
            cpu_cores: batch.node_capacity.cpu_cores,
            memory_bytes: batch.node_capacity.memory_bytes,
            bpf_runq_enqueued: batch.bpf_occupancy.runq_enqueued,
            bpf_runq_hist: batch.bpf_occupancy.runq_hist,
            bpf_pair: batch.bpf_occupancy.pair,
            unknown_blame_share: batch.unknown_blame_share,
            updated_at: now,
        }
    }
}

/// A stored history row (minute or five-minute). Positional — matches
/// `schema::pod_compute_history`. This is also what the findings engine
/// consumes, so tests build these directly.
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable, PartialEq)]
#[diesel(table_name = crate::schema::pod_compute_history)]
pub struct PodComputeHistoryRow {
    pub id: i64,
    pub container_uid: String,
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub container: String,
    pub node: String,
    pub ts: NaiveDateTime,
    pub resolution_secs: i32,
    pub cpu_usage_millis_avg: f64,
    pub cpu_usage_millis_max: f64,
    pub cpu_usage_millis_last: f64,
    pub cpu_quota_usec: Option<i64>,
    pub cpu_period_usec: i64,
    pub cpu_request_millis: Option<i64>,
    pub cpu_limit_millis: Option<i64>,
    pub cpu_nr_periods: i64,
    pub cpu_nr_throttled: i64,
    pub cpu_throttled_usec: i64,
    pub cpu_psi_some10_avg: f64,
    pub cpu_psi_some10_max: f64,
    pub cpu_psi_full10_avg: f64,
    pub cpu_psi_full10_max: f64,
    pub mem_current_avg: i64,
    pub mem_current_max: i64,
    pub mem_current_last: i64,
    pub mem_working_set_avg: i64,
    pub mem_working_set_max: i64,
    pub mem_working_set_last: i64,
    pub mem_limit: Option<i64>,
    pub mem_request: Option<i64>,
    pub mem_psi_some10_avg: f64,
    pub mem_psi_some10_max: f64,
    pub mem_psi_full10_avg: f64,
    pub mem_psi_full10_max: f64,
    pub mem_events_high: i64,
    pub mem_events_max: i64,
    pub mem_oom_kill: i64,
    pub mem_refault: i64,
    pub mem_pgmajfault: i64,
    pub runq_count: Option<i64>,
    pub runq_p50_us: Option<i64>,
    pub runq_p95_us: Option<i64>,
    pub runq_p99_us: Option<i64>,
    pub runq_max_us: Option<i64>,
    pub runq_overflow: Option<i64>,
    pub runq_hist: Option<Vec<i64>>,
}

/// Insertable half of `PodComputeHistoryRow` (no `id`).
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::pod_compute_history)]
pub struct NewPodComputeHistory {
    pub container_uid: String,
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub container: String,
    pub node: String,
    pub ts: NaiveDateTime,
    pub resolution_secs: i32,
    pub cpu_usage_millis_avg: f64,
    pub cpu_usage_millis_max: f64,
    pub cpu_usage_millis_last: f64,
    pub cpu_quota_usec: Option<i64>,
    pub cpu_period_usec: i64,
    pub cpu_request_millis: Option<i64>,
    pub cpu_limit_millis: Option<i64>,
    pub cpu_nr_periods: i64,
    pub cpu_nr_throttled: i64,
    pub cpu_throttled_usec: i64,
    pub cpu_psi_some10_avg: f64,
    pub cpu_psi_some10_max: f64,
    pub cpu_psi_full10_avg: f64,
    pub cpu_psi_full10_max: f64,
    pub mem_current_avg: i64,
    pub mem_current_max: i64,
    pub mem_current_last: i64,
    pub mem_working_set_avg: i64,
    pub mem_working_set_max: i64,
    pub mem_working_set_last: i64,
    pub mem_limit: Option<i64>,
    pub mem_request: Option<i64>,
    pub mem_psi_some10_avg: f64,
    pub mem_psi_some10_max: f64,
    pub mem_psi_full10_avg: f64,
    pub mem_psi_full10_max: f64,
    pub mem_events_high: i64,
    pub mem_events_max: i64,
    pub mem_oom_kill: i64,
    pub mem_refault: i64,
    pub mem_pgmajfault: i64,
    pub runq_count: Option<i64>,
    pub runq_p50_us: Option<i64>,
    pub runq_p95_us: Option<i64>,
    pub runq_p99_us: Option<i64>,
    pub runq_max_us: Option<i64>,
    pub runq_overflow: Option<i64>,
    pub runq_hist: Option<Vec<i64>>,
}

/// Byte gauges arrive as f64 (an average of byte counts is fractional)
/// and are stored as BIGINT; round rather than truncate so a 0.6 byte
/// average does not read as zero.
fn bytes(v: f64) -> i64 {
    if v.is_finite() {
        v.round() as i64
    } else {
        0
    }
}

impl NewPodComputeHistory {
    pub fn from_history(batch: &ComputeHistoryBatch, c: &ComputeHistoryContainer) -> Self {
        let runq = c.runq.as_ref();
        NewPodComputeHistory {
            container_uid: c.container_uid.clone(),
            pod_uid: c.pod_uid.clone(),
            namespace: c.namespace.clone(),
            pod_name: c.pod_name.clone(),
            container: c.container.clone(),
            node: batch.node.clone(),
            ts: batch.ts.naive_utc(),
            resolution_secs: batch.resolution_secs,
            cpu_usage_millis_avg: c.cpu.usage_millis.avg,
            cpu_usage_millis_max: c.cpu.usage_millis.max,
            cpu_usage_millis_last: c.cpu.usage_millis.last,
            cpu_quota_usec: c.cpu.quota_usec,
            cpu_period_usec: c.cpu.period_usec,
            cpu_request_millis: c.cpu.request_millis,
            cpu_limit_millis: c.cpu.limit_millis,
            cpu_nr_periods: c.cpu.nr_periods,
            cpu_nr_throttled: c.cpu.nr_throttled,
            cpu_throttled_usec: c.cpu.throttled_usec,
            cpu_psi_some10_avg: c.cpu.psi_some10.avg,
            cpu_psi_some10_max: c.cpu.psi_some10.max,
            cpu_psi_full10_avg: c.cpu.psi_full10.avg,
            cpu_psi_full10_max: c.cpu.psi_full10.max,
            mem_current_avg: bytes(c.memory.current.avg),
            mem_current_max: bytes(c.memory.current.max),
            mem_current_last: bytes(c.memory.current.last),
            mem_working_set_avg: bytes(c.memory.working_set.avg),
            mem_working_set_max: bytes(c.memory.working_set.max),
            mem_working_set_last: bytes(c.memory.working_set.last),
            mem_limit: c.memory.limit,
            mem_request: c.memory.request,
            mem_psi_some10_avg: c.memory.psi_some10.avg,
            mem_psi_some10_max: c.memory.psi_some10.max,
            mem_psi_full10_avg: c.memory.psi_full10.avg,
            mem_psi_full10_max: c.memory.psi_full10.max,
            mem_events_high: c.memory.events_high,
            mem_events_max: c.memory.events_max,
            mem_oom_kill: c.memory.oom_kill,
            mem_refault: c.memory.refault,
            mem_pgmajfault: c.memory.pgmajfault,
            runq_count: runq.map(|r| r.count),
            runq_p50_us: runq.map(|r| r.p50_us),
            runq_p95_us: runq.map(|r| r.p95_us),
            runq_p99_us: runq.map(|r| r.p99_us),
            runq_max_us: runq.map(|r| r.max_us),
            runq_overflow: runq.map(|r| r.overflow),
            runq_hist: runq.filter(|r| !r.hist.is_empty()).map(|r| r.hist.clone()),
        }
    }
}

/// A stored blame pair. Positional — matches
/// `schema::pod_contention_history`.
#[derive(
    Debug, Clone, Serialize, Deserialize, Queryable, QueryableByName, Identifiable, PartialEq,
)]
#[diesel(table_name = crate::schema::pod_contention_history)]
pub struct PodContentionRow {
    pub id: i64,
    pub ts: NaiveDateTime,
    pub node: String,
    pub victim_container_uid: String,
    pub victim_pod_uid: String,
    pub victim_namespace: String,
    pub culprit_cgroup_id: i64,
    pub culprit_kind: String,
    pub culprit_ref: String,
    pub culprit_container_uid: Option<String>,
    pub count: i64,
    pub wait_ns: i64,
}

/// Insertable half of `PodContentionRow` (no `id`).
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::pod_contention_history)]
pub struct NewPodContention {
    pub ts: NaiveDateTime,
    pub node: String,
    pub victim_container_uid: String,
    pub victim_pod_uid: String,
    pub victim_namespace: String,
    pub culprit_cgroup_id: i64,
    pub culprit_kind: String,
    pub culprit_ref: String,
    pub culprit_container_uid: Option<String>,
    pub count: i64,
    pub wait_ns: i64,
}

impl NewPodContention {
    pub fn from_blame(
        batch: &ComputeHistoryBatch,
        c: &ComputeHistoryContainer,
        b: &BlameEntry,
    ) -> Self {
        NewPodContention {
            ts: batch.ts.naive_utc(),
            node: batch.node.clone(),
            victim_container_uid: c.container_uid.clone(),
            victim_pod_uid: c.pod_uid.clone(),
            victim_namespace: c.namespace.clone(),
            culprit_cgroup_id: cgroup_id_to_db(b.cgroup_id),
            culprit_kind: b.kind.clone(),
            culprit_ref: b.reference.clone(),
            culprit_container_uid: b.container_uid.clone(),
            count: b.count,
            wait_ns: b.wait_ns,
        }
    }
}

// ---------------------------------------------------------------------
// Findings (GET /compute/findings)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    NoisyNeighbor,
    CpuThrottled,
    CpuContended,
    MemoryPressure,
    MemoryLimitThrash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingVictim {
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub container: String,
    pub container_uid: String,
    pub node: String,
}

/// The neighbour named by a `noisy-neighbor` / `memory-pressure`
/// finding. `kind` is `pod`, `system` or `kernel` — never `unknown`; an
/// unknown-dominated blame list produces no culprit at all. The pod
/// identity fields are `null` for non-pod culprits, and `blame_share` is
/// the culprit's fraction of the victim's total wait over the window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingCulprit {
    pub kind: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub pod_uid: Option<String>,
    pub namespace: Option<String>,
    pub pod_name: Option<String>,
    pub container_uid: Option<String>,
    pub blame_share: f64,
    pub cpu_usage_millis: f64,
    pub cpu_request_millis: Option<i64>,
}

/// The numbers that fired the rule, so the UI and the assistant show
/// evidence rather than a verdict. `runq_p99_us_max` is `null` when the
/// scheduler probe was not loaded for the victim's node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingEvidence {
    pub window_minutes: i64,
    pub cpu_psi_some10_max: f64,
    pub cpu_psi_full10_max: f64,
    pub runq_p99_us_max: Option<i64>,
    pub throttled_ratio: f64,
    pub mem_psi_some10_max: f64,
    pub node_mem_some10_max: f64,
    pub refault_delta: i64,
    pub mem_events_high_delta: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub victim: FindingVictim,
    pub culprit: Option<FindingCulprit>,
    pub evidence: FindingEvidence,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract's example envelope, verbatim field names.
    const SAMPLE: &str = r#"{
      "node": "worker-3",
      "ts": "2026-09-10T02:41:05Z",
      "interval_ms": 5000,
      "ctxt_per_sec": 41250.0,
      "compute_enabled": true, "compute_supported": true, "contention_loaded": false,
      "node_pressure": { "cpu_some10": 3.1, "cpu_full10": 0.0, "mem_some10": 0.0, "mem_full10": 0.0 },
      "node_capacity": { "cpu_cores": 32, "memory_bytes": 137438953472 },
      "bpf_occupancy": { "runq_enqueued": 0, "runq_hist": 0, "pair": 0 },
      "unknown_blame_share": 0.0,
      "containers": [{
        "container_uid": "abc/api",
        "pod_uid": "abc", "pod_name": "api-7c9", "namespace": "payments", "container": "api",
        "cgroup_id": 18944,
        "cpu": { "usage_usec": 412000, "quota_usec": 500000, "period_usec": 100000,
                 "request_millis": 250, "limit_millis": 500,
                 "nr_periods": 50, "nr_throttled": 2, "throttled_usec": 8100,
                 "psi_some10": 12.4, "psi_full10": 0.8 },
        "memory": { "current": 183500800, "working_set": 171000000, "limit": 268435456, "request": 134217728,
                    "psi_some10": 0.0, "psi_full10": 0.0,
                    "events_high": 0, "events_max": 0, "oom_kill": 0,
                    "refault": 120, "pgmajfault": 0 },
        "runq": { "count": 340, "p50_us": 90, "p95_us": 1800, "p99_us": 24000, "max_us": 61000, "overflow": 0,
                  "hist": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] },
        "blame": [ { "cgroup_id": 21003, "kind": "pod", "ref": "batch/etl-1-x/worker", "container_uid": "u/worker", "count": 210, "wait_ns": 6100000000 },
                   { "cgroup_id": 77, "kind": "system", "ref": "system.slice/kubelet.service", "container_uid": null, "count": 40, "wait_ns": 300000000 } ]
      }]
    }"#;

    #[test]
    fn batch_parses_contract_example_and_flattens_to_row() {
        let batch: ComputeBatch = serde_json::from_str(SAMPLE).expect("contract example parses");
        assert_eq!(batch.node, "worker-3");
        assert_eq!(batch.containers.len(), 1);
        let now = NaiveDateTime::default();
        let row = PodComputeLatest::from_sample(&batch, &batch.containers[0], now);
        assert_eq!(row.container_uid, "abc/api");
        assert_eq!(row.node, "worker-3");
        assert_eq!(row.ts.to_string(), "2026-09-10 02:41:05");
        // 412000 µs over a 5000 ms interval = 82.4 millicores.
        assert!((row.cpu_usage_millis - 82.4).abs() < 1e-9);
        assert_eq!(row.cpu_quota_usec, Some(500_000));
        assert_eq!(row.runq_p99_us, Some(24_000));
        assert_eq!(row.blame.as_array().map(|a| a.len()), Some(2));
        assert_eq!(row.blame[0]["ref"], "batch/etl-1-x/worker");
        assert_eq!(row.blame[1]["container_uid"], serde_json::Value::Null);
        let node = NodeComputeLatest::from_batch(&batch, now);
        assert_eq!(node.cpu_cores, 32);
        assert!(!node.contention_loaded);
    }

    #[test]
    fn runq_null_when_probe_not_loaded() {
        let mut v: serde_json::Value = serde_json::from_str(SAMPLE).unwrap();
        v["containers"][0]["runq"] = serde_json::Value::Null;
        v["containers"][0]["cpu"]["quota_usec"] = serde_json::Value::Null;
        let batch: ComputeBatch = serde_json::from_value(v).unwrap();
        let row =
            PodComputeLatest::from_sample(&batch, &batch.containers[0], NaiveDateTime::default());
        assert_eq!(row.runq_count, None);
        assert_eq!(row.runq_p99_us, None);
        assert_eq!(row.cpu_quota_usec, None);
    }

    #[test]
    fn usage_millis_is_millicores() {
        // One full core for 5 s = 5_000_000 µs → 1000 m.
        assert_eq!(usage_millis(5_000_000, 5000), 1000.0);
        assert_eq!(usage_millis(1_000, 0), 0.0);
        assert_eq!(usage_millis(1_000, -5), 0.0);
    }

    #[test]
    fn cgroup_id_high_bit_round_trips() {
        let id = u64::MAX - 5;
        assert_eq!(cgroup_id_to_db(id) as u64, id);
    }

    #[test]
    fn history_envelope_parses_gauge_objects() {
        let json = r#"{
          "node": "worker-3", "ts": "2026-09-10T02:41:00Z", "interval_ms": 60000, "resolution_secs": 60,
          "ctxt_per_sec": 1.0,
          "containers": [{
            "container_uid": "abc/api", "pod_uid": "abc", "pod_name": "api", "namespace": "payments",
            "container": "api", "cgroup_id": 1,
            "cpu": { "usage_millis": {"avg": 80.5, "max": 120.0, "last": 90.0}, "quota_usec": null,
                     "period_usec": 100000, "request_millis": 250, "limit_millis": null,
                     "nr_periods": 600, "nr_throttled": 0, "throttled_usec": 0,
                     "psi_some10": {"avg": 1.0, "max": 2.0, "last": 1.5},
                     "psi_full10": {"avg": 0.0, "max": 0.0, "last": 0.0} },
            "memory": { "current": {"avg": 100.6, "max": 200.0, "last": 150.0},
                        "working_set": {"avg": 90.0, "max": 100.0, "last": 95.0},
                        "limit": 1000, "request": 500,
                        "psi_some10": {"avg": 0.0, "max": 0.0, "last": 0.0},
                        "psi_full10": {"avg": 0.0, "max": 0.0, "last": 0.0},
                        "events_high": 3, "events_max": 0, "oom_kill": 0, "refault": 7, "pgmajfault": 0 },
            "runq": null,
            "blame": [ { "cgroup_id": 9, "kind": "system", "ref": "system.slice/kubelet.service", "container_uid": null, "count": 4, "wait_ns": 100 } ]
          }]
        }"#;
        let batch: ComputeHistoryBatch = serde_json::from_str(json).unwrap();
        let c = &batch.containers[0];
        let row = NewPodComputeHistory::from_history(&batch, c);
        assert_eq!(row.resolution_secs, 60);
        assert_eq!(row.cpu_usage_millis_avg, 80.5);
        assert_eq!(
            row.mem_current_avg, 101,
            "byte averages round, not truncate"
        );
        assert_eq!(row.mem_events_high, 3);
        assert_eq!(row.runq_hist, None);
        let pair = NewPodContention::from_blame(&batch, c, &c.blame[0]);
        assert_eq!(pair.victim_container_uid, "abc/api");
        assert_eq!(pair.culprit_kind, "system");
        assert_eq!(pair.culprit_container_uid, None);
    }

    #[test]
    fn finding_serialises_with_contract_names() {
        let f = Finding {
            kind: FindingKind::NoisyNeighbor,
            severity: Severity::High,
            victim: FindingVictim {
                pod_uid: "v".into(),
                namespace: "payments".into(),
                pod_name: "api".into(),
                container: "api".into(),
                container_uid: "v/api".into(),
                node: "n".into(),
            },
            culprit: Some(FindingCulprit {
                kind: "pod".into(),
                reference: "batch/etl/worker".into(),
                pod_uid: Some("c".into()),
                namespace: Some("batch".into()),
                pod_name: Some("etl".into()),
                container_uid: Some("c/worker".into()),
                blame_share: 0.71,
                cpu_usage_millis: 1900.0,
                cpu_request_millis: Some(500),
            }),
            evidence: FindingEvidence {
                window_minutes: 5,
                cpu_psi_some10_max: 31.0,
                cpu_psi_full10_max: 4.2,
                runq_p99_us_max: Some(48_000),
                throttled_ratio: 0.02,
                mem_psi_some10_max: 0.0,
                node_mem_some10_max: 0.0,
                refault_delta: 0,
                mem_events_high_delta: 0,
            },
            first_seen: NaiveDateTime::default(),
            last_seen: NaiveDateTime::default(),
            message: "m".into(),
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["kind"], "noisy-neighbor");
        assert_eq!(v["severity"], "high");
        assert_eq!(v["culprit"]["ref"], "batch/etl/worker");
        assert_eq!(v["evidence"]["runq_p99_us_max"], 48_000);
        assert_eq!(
            serde_json::to_value(FindingKind::MemoryLimitThrash).unwrap(),
            "memory-limit-thrash"
        );
        assert!(Severity::Critical > Severity::High && Severity::High > Severity::Medium);
    }
}
