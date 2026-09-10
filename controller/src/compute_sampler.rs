//! Compute sampler: usage and stall gauges from cgroup v2 files, blame
//! from the scheduler-contention probe, shipped to the broker at two
//! cadences (design D2, D4, D5).
//!
//! Every `sample_interval` the loop reads, per registered container and
//! per pod-level cgroup, the handful of cgroup v2 files the kernel
//! already keeps exact counters in (`cpu.stat`, `cpu.max`,
//! `cpu.pressure`, `memory.current`, `memory.max`, `memory.stat`,
//! `memory.pressure`, `memory.events`), plus the node's `/proc/pressure`,
//! `/proc/stat` and `/proc/meminfo`. Counters are shipped as deltas over
//! the interval; gauges as instantaneous values. Every 60 s the samples
//! collected since the last fold are reduced to one minute row per
//! container (avg/max/last for gauges, sums for counters, summed
//! histogram, top-10 blame pairs) and posted to the history endpoint.
//!
//! The file walk runs inside `spawn_blocking`: ~10 small reads per
//! container is cheap but it is synchronous IO, and the supervisor
//! module documents why a blocking call on a worker is not free.
//!
//! The scheduler probe is reached only through [`ContentionSource`], so
//! this module compiles and is fully testable without a loaded BPF
//! program; `main` wires the real `contention::ContentionProbe` in.
//!
//! Broker outage: like the network batcher, failed POSTs are held for
//! retry on the next tick and the pending queue is capped, oldest
//! dropped first.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::client::api_post_call;
use crate::compute_config::ComputeConfig;
use crate::compute_registry::{
    cgroup_id_for_full_path, ComputeMap, ComputeRegistration, ContainerCompute, ResourceSpec,
};
use crate::contention::{quantiles_from_hist, ContentionSnapshot, MapOccupancy, PairDelta};
use crate::error::Error;

/// Where the scheduler-contention data comes from. `main` hands the
/// sampler the real `ContentionProbe`; tests hand it a fake.
pub trait ContentionSource: Send {
    fn track(&self, cgroup_id: u64) -> anyhow::Result<()>;
    fn untrack(&self, cgroup_id: u64) -> anyhow::Result<()>;
    fn snapshot(&mut self) -> anyhow::Result<ContentionSnapshot>;
}

impl ContentionSource for crate::contention::ContentionProbe {
    fn track(&self, cgroup_id: u64) -> anyhow::Result<()> {
        crate::contention::ContentionProbe::track(self, cgroup_id).map_err(anyhow::Error::from)
    }
    fn untrack(&self, cgroup_id: u64) -> anyhow::Result<()> {
        crate::contention::ContentionProbe::untrack(self, cgroup_id).map_err(anyhow::Error::from)
    }
    fn snapshot(&mut self) -> anyhow::Result<ContentionSnapshot> {
        crate::contention::ContentionProbe::snapshot(self).map_err(anyhow::Error::from)
    }
}

/// How often the `/sys/fs/cgroup` id→path index is rebuilt for culprit
/// resolution. Only maintained while a probe is loaded.
const CGROUP_INDEX_REFRESH: Duration = Duration::from_secs(30);
/// Minimum ticks between index rebuilds triggered by an unresolved
/// culprit, so a stream of transient scopes cannot force a full walk
/// every tick.
const ONDEMAND_REBUILD_EVERY_TICKS: u64 = 6;
/// Upper bound on directories visited per index walk.
pub const CGROUP_INDEX_LIMIT: usize = 20_000;
/// Fold cadence for the history endpoint.
const HISTORY_INTERVAL: Duration = Duration::from_secs(60);
/// Containers per POST. A 1 000-container node must never produce one
/// body the broker rejects and the queue retries forever.
pub const MAX_CONTAINERS_PER_POST: usize = 250;

/// How many sample ticks make one history row: `60 / sampleInterval`
/// (12 at the default 5 s), never fewer than one.
pub fn fold_size(sample_interval: Duration) -> u32 {
    let secs = sample_interval.as_secs().max(1);
    (HISTORY_INTERVAL.as_secs() / secs).max(1) as u32
}
/// Pending POSTs held across a broker outage, in TICKS: the newest 24
/// ticks' worth of chunks (two minutes at 5 s) are kept whatever the
/// chunk count per tick; older ticks are dropped first.
const MAX_PENDING_TICKS: usize = 24;
/// Blame entries shipped per victim per sample.
const SAMPLE_BLAME_LIMIT: usize = 20;
/// Blame entries shipped per victim per minute.
const HISTORY_BLAME_LIMIT: usize = 10;

pub const SAMPLE_PATH: &str = "pod/compute/batch";
pub const HISTORY_PATH: &str = "pod/compute/history/batch";

// ---------------------------------------------------------------------------
// Parsed cgroup and /proc files (pure, fixture-tested)
// ---------------------------------------------------------------------------

/// `cpu.stat`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuStat {
    pub usage_usec: u64,
    pub user_usec: u64,
    pub system_usec: u64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
}

/// `cpu.max`: `max 100000` or `50000 100000`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMax {
    pub quota_usec: Option<u64>,
    pub period_usec: u64,
}

impl Default for CpuMax {
    fn default() -> Self {
        Self {
            quota_usec: None,
            period_usec: 100_000,
        }
    }
}

/// A PSI file (`cpu.pressure`, `memory.pressure`, `/proc/pressure/*`).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Pressure {
    pub some_avg10: f64,
    pub some_avg60: f64,
    pub some_total: u64,
    pub full_avg10: f64,
    pub full_avg60: f64,
    pub full_total: u64,
}

/// The fields of `memory.stat` this feature keeps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemStat {
    pub anon: u64,
    pub file: u64,
    pub inactive_file: u64,
    pub workingset_refault_anon: u64,
    pub workingset_refault_file: u64,
    pub pgmajfault: u64,
}

/// `memory.events`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemEvents {
    pub low: u64,
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
}

fn kv_lines(body: &str) -> impl Iterator<Item = (&str, &str)> {
    body.lines().filter_map(|l| {
        let mut it = l.split_whitespace();
        Some((it.next()?, it.next()?))
    })
}

pub fn parse_cpu_stat(body: &str) -> CpuStat {
    let mut s = CpuStat::default();
    for (k, v) in kv_lines(body) {
        let Ok(n) = v.parse::<u64>() else { continue };
        match k {
            "usage_usec" => s.usage_usec = n,
            "user_usec" => s.user_usec = n,
            "system_usec" => s.system_usec = n,
            "nr_periods" => s.nr_periods = n,
            "nr_throttled" => s.nr_throttled = n,
            "throttled_usec" => s.throttled_usec = n,
            _ => {}
        }
    }
    s
}

pub fn parse_cpu_max(body: &str) -> CpuMax {
    let mut it = body.split_whitespace();
    let quota = it.next();
    let period = it.next().and_then(|p| p.parse::<u64>().ok());
    let quota_usec = match quota {
        Some("max") | None => None,
        Some(q) => q.parse::<u64>().ok(),
    };
    CpuMax {
        quota_usec,
        period_usec: period.unwrap_or(100_000),
    }
}

/// `some avg10=0.00 avg60=0.00 avg300=0.00 total=0` / `full …`. `None`
/// when neither line parses (a file that is not PSI at all).
pub fn parse_pressure(body: &str) -> Option<Pressure> {
    let mut p = Pressure::default();
    let mut seen = false;
    for line in body.lines() {
        let mut it = line.split_whitespace();
        let kind = it.next();
        let mut avg10 = 0.0;
        let mut avg60 = 0.0;
        let mut total = 0u64;
        for field in it {
            if let Some((k, v)) = field.split_once('=') {
                match k {
                    "avg10" => avg10 = v.parse().unwrap_or(0.0),
                    "avg60" => avg60 = v.parse().unwrap_or(0.0),
                    "total" => total = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        match kind {
            Some("some") => {
                p.some_avg10 = avg10;
                p.some_avg60 = avg60;
                p.some_total = total;
                seen = true;
            }
            Some("full") => {
                p.full_avg10 = avg10;
                p.full_avg60 = avg60;
                p.full_total = total;
                seen = true;
            }
            _ => {}
        }
    }
    seen.then_some(p)
}

pub fn parse_memory_stat(body: &str) -> MemStat {
    let mut s = MemStat::default();
    for (k, v) in kv_lines(body) {
        let Ok(n) = v.parse::<u64>() else { continue };
        match k {
            "anon" => s.anon = n,
            "file" => s.file = n,
            "inactive_file" => s.inactive_file = n,
            "workingset_refault_anon" => s.workingset_refault_anon = n,
            "workingset_refault_file" => s.workingset_refault_file = n,
            // Older kernels (< 5.9) have a single counter.
            "workingset_refault" => s.workingset_refault_file = n,
            "pgmajfault" => s.pgmajfault = n,
            _ => {}
        }
    }
    s
}

pub fn parse_memory_events(body: &str) -> MemEvents {
    let mut e = MemEvents::default();
    for (k, v) in kv_lines(body) {
        let Ok(n) = v.parse::<u64>() else { continue };
        match k {
            "low" => e.low = n,
            "high" => e.high = n,
            "max" => e.max = n,
            "oom" => e.oom = n,
            "oom_kill" => e.oom_kill = n,
            _ => {}
        }
    }
    e
}

/// `memory.max` / `memory.high`: a byte count or `max`.
pub fn parse_u64_or_max(body: &str) -> Option<u64> {
    let t = body.trim();
    if t == "max" || t.is_empty() {
        return None;
    }
    t.parse().ok()
}

/// cAdvisor's working set: `memory.current − inactive_file`, floored at 0.
pub fn working_set(current: u64, inactive_file: u64) -> u64 {
    current.saturating_sub(inactive_file)
}

/// `/proc/stat`: the `ctxt` counter and the number of `cpuN` lines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcStat {
    pub ctxt: u64,
    pub cpus: u32,
}

pub fn parse_proc_stat(body: &str) -> ProcStat {
    let mut s = ProcStat::default();
    for line in body.lines() {
        let mut it = line.split_whitespace();
        match it.next() {
            Some("ctxt") => s.ctxt = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            Some(k)
                if k.starts_with("cpu")
                    && k.len() > 3
                    && k[3..].chars().all(|c| c.is_ascii_digit()) =>
            {
                s.cpus += 1
            }
            _ => {}
        }
    }
    s
}

/// `MemTotal` from `/proc/meminfo`, in bytes.
pub fn parse_meminfo_total_bytes(body: &str) -> Option<u64> {
    body.lines().find_map(|l| {
        let rest = l.strip_prefix("MemTotal:")?;
        let mut it = rest.split_whitespace();
        let n: u64 = it.next()?.parse().ok()?;
        let unit = it.next().unwrap_or("kB");
        Some(match unit {
            "kB" | "KB" | "kb" => n * 1024,
            "MB" | "mB" => n * 1024 * 1024,
            _ => n,
        })
    })
}

// ---------------------------------------------------------------------------
// Reading one cgroup
// ---------------------------------------------------------------------------

/// Everything read from one cgroup directory in one pass.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CgroupRaw {
    pub cpu: CpuStat,
    pub cpu_max: CpuMax,
    pub cpu_psi: Option<Pressure>,
    pub mem_current: u64,
    pub mem_max: Option<u64>,
    pub mem_stat: MemStat,
    pub mem_psi: Option<Pressure>,
    pub mem_events: MemEvents,
}

fn read_opt(dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(name)).ok()
}

/// Read a cgroup. `cpu.stat` is mandatory (its absence means the
/// directory is gone or is not a cgroup); every other file degrades to
/// its default so a kernel without PSI or a cgroup without the memory
/// controller still yields a usage gauge.
pub fn read_cgroup(dir: &Path) -> io::Result<CgroupRaw> {
    let cpu = std::fs::read_to_string(dir.join("cpu.stat"))?;
    Ok(CgroupRaw {
        cpu: parse_cpu_stat(&cpu),
        cpu_max: read_opt(dir, "cpu.max")
            .map(|b| parse_cpu_max(&b))
            .unwrap_or_default(),
        cpu_psi: read_opt(dir, "cpu.pressure").and_then(|b| parse_pressure(&b)),
        mem_current: read_opt(dir, "memory.current")
            .and_then(|b| b.trim().parse().ok())
            .unwrap_or(0),
        mem_max: read_opt(dir, "memory.max").and_then(|b| parse_u64_or_max(&b)),
        mem_stat: read_opt(dir, "memory.stat")
            .map(|b| parse_memory_stat(&b))
            .unwrap_or_default(),
        mem_psi: read_opt(dir, "memory.pressure").and_then(|b| parse_pressure(&b)),
        mem_events: read_opt(dir, "memory.events")
            .map(|b| parse_memory_events(&b))
            .unwrap_or_default(),
    })
}

/// The monotonically increasing counters of a cgroup, for deltas.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub usage_usec: u64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
    pub events_high: u64,
    pub events_max: u64,
    pub oom_kill: u64,
    pub refault: u64,
    pub pgmajfault: u64,
}

impl Counters {
    pub fn from_raw(r: &CgroupRaw) -> Self {
        Self {
            usage_usec: r.cpu.usage_usec,
            nr_periods: r.cpu.nr_periods,
            nr_throttled: r.cpu.nr_throttled,
            throttled_usec: r.cpu.throttled_usec,
            events_high: r.mem_events.high,
            events_max: r.mem_events.max,
            oom_kill: r.mem_events.oom_kill,
            refault: r
                .mem_stat
                .workingset_refault_anon
                .saturating_add(r.mem_stat.workingset_refault_file),
            pgmajfault: r.mem_stat.pgmajfault,
        }
    }

    /// `cur − prev`, or `None` if any counter went backwards (the cgroup
    /// was recreated under the same id, which the kernel does not do,
    /// or the files were reset — either way the delta is meaningless).
    pub fn delta(prev: &Counters, cur: &Counters) -> Option<Counters> {
        Some(Counters {
            usage_usec: cur.usage_usec.checked_sub(prev.usage_usec)?,
            nr_periods: cur.nr_periods.checked_sub(prev.nr_periods)?,
            nr_throttled: cur.nr_throttled.checked_sub(prev.nr_throttled)?,
            throttled_usec: cur.throttled_usec.checked_sub(prev.throttled_usec)?,
            events_high: cur.events_high.checked_sub(prev.events_high)?,
            events_max: cur.events_max.checked_sub(prev.events_max)?,
            oom_kill: cur.oom_kill.checked_sub(prev.oom_kill)?,
            refault: cur.refault.checked_sub(prev.refault)?,
            pgmajfault: cur.pgmajfault.checked_sub(prev.pgmajfault)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Wire types — `POST /pod/compute/batch`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct NodePressure {
    pub cpu_some10: f64,
    pub cpu_full10: f64,
    pub mem_some10: f64,
    pub mem_full10: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct NodeCapacity {
    pub cpu_cores: u32,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct BpfOccupancy {
    pub runq_enqueued: u64,
    pub runq_hist: u64,
    pub pair: u64,
    /// Map-full insert failures during this interval (additive to the
    /// contract; the kernel counters are cumulative, the sampler ships
    /// the delta): any non-zero value means samples were lost in kernel.
    pub hist_update_failures: u64,
    pub pair_update_failures: u64,
}

/// Per-interval insert-failure deltas from cumulative kernel counters.
/// Returns `(hist_delta, pair_delta, new_prev)`; a counter that went
/// backwards (probe reloaded) re-baselines to zero for that interval.
pub(crate) fn failure_deltas(prev: (u64, u64), m: &MapOccupancy) -> (u64, u64, (u64, u64)) {
    let hist = m.hist_update_failures.saturating_sub(prev.0);
    let pair = m.pair_update_failures.saturating_sub(prev.1);
    (hist, pair, (m.hist_update_failures, m.pair_update_failures))
}

impl From<&MapOccupancy> for BpfOccupancy {
    fn from(m: &MapOccupancy) -> Self {
        Self {
            runq_enqueued: m.runq_enqueued,
            runq_hist: m.runq_hist,
            pair: m.pair,
            hist_update_failures: m.hist_update_failures,
            pair_update_failures: m.pair_update_failures,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpuSample {
    pub usage_usec: u64,
    pub quota_usec: Option<u64>,
    pub period_usec: u64,
    pub request_millis: Option<u64>,
    pub limit_millis: Option<u64>,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
    pub psi_some10: f64,
    pub psi_full10: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MemSample {
    pub current: u64,
    pub working_set: u64,
    pub limit: Option<u64>,
    pub request: Option<u64>,
    pub psi_some10: f64,
    pub psi_full10: f64,
    pub events_high: u64,
    pub events_max: u64,
    pub oom_kill: u64,
    pub refault: u64,
    pub pgmajfault: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RunqSample {
    pub count: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub overflow: u64,
    pub hist: [u64; 24],
}

impl RunqSample {
    pub fn from_hist(hist: [u64; 24]) -> Self {
        let q = quantiles_from_hist(&hist);
        Self {
            count: q.count,
            p50_us: q.p50_us,
            p95_us: q.p95_us,
            p99_us: q.p99_us,
            max_us: q.max_us,
            overflow: q.overflow,
            hist,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BlameEntry {
    pub cgroup_id: u64,
    pub kind: &'static str,
    #[serde(rename = "ref")]
    pub reference: String,
    pub container_uid: Option<String>,
    pub count: u64,
    pub wait_ns: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ContainerSample {
    pub container_uid: String,
    pub pod_uid: String,
    pub pod_name: String,
    pub namespace: String,
    pub container: String,
    pub cgroup_id: u64,
    pub cpu: CpuSample,
    pub memory: MemSample,
    pub runq: Option<RunqSample>,
    pub blame: Vec<BlameEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ComputeBatch {
    pub node: String,
    pub ts: String,
    pub interval_ms: u64,
    pub ctxt_per_sec: f64,
    pub compute_enabled: bool,
    pub compute_supported: bool,
    pub contention_loaded: bool,
    pub node_pressure: NodePressure,
    pub node_capacity: NodeCapacity,
    pub bpf_occupancy: BpfOccupancy,
    pub unknown_blame_share: f64,
    pub containers: Vec<ContainerSample>,
}

// ---------------------------------------------------------------------------
// Wire types — `POST /pod/compute/history/batch`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Default)]
pub struct Gauge {
    pub avg: f64,
    pub max: f64,
    pub last: f64,
}

#[derive(Debug, Clone, Copy, Default)]
struct GaugeAcc {
    sum: f64,
    max: f64,
    last: f64,
    n: u32,
}

impl GaugeAcc {
    fn push(&mut self, v: f64) {
        if self.n == 0 || v > self.max {
            self.max = v;
        }
        self.sum += v;
        self.last = v;
        self.n += 1;
    }
    fn gauge(&self) -> Gauge {
        Gauge {
            avg: if self.n == 0 {
                0.0
            } else {
                self.sum / f64::from(self.n)
            },
            max: self.max,
            last: self.last,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HistoryCpu {
    pub usage_usec: u64,
    pub usage_millis: Gauge,
    pub quota_usec: Option<u64>,
    pub period_usec: u64,
    pub request_millis: Option<u64>,
    pub limit_millis: Option<u64>,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
    pub psi_some10: Gauge,
    pub psi_full10: Gauge,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HistoryMem {
    pub current: Gauge,
    pub working_set: Gauge,
    pub limit: Option<u64>,
    pub request: Option<u64>,
    pub psi_some10: Gauge,
    pub psi_full10: Gauge,
    pub events_high: u64,
    pub events_max: u64,
    pub oom_kill: u64,
    pub refault: u64,
    pub pgmajfault: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HistoryContainer {
    pub container_uid: String,
    pub pod_uid: String,
    pub pod_name: String,
    pub namespace: String,
    pub container: String,
    pub cgroup_id: u64,
    pub samples: u32,
    pub cpu: HistoryCpu,
    pub memory: HistoryMem,
    pub runq: Option<RunqSample>,
    pub blame: Vec<BlameEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HistoryBatch {
    pub node: String,
    pub ts: String,
    pub interval_ms: u64,
    pub resolution_secs: u64,
    pub ctxt_per_sec: f64,
    pub compute_enabled: bool,
    pub compute_supported: bool,
    pub contention_loaded: bool,
    pub node_pressure: NodePressure,
    pub node_capacity: NodeCapacity,
    pub bpf_occupancy: BpfOccupancy,
    pub unknown_blame_share: f64,
    pub containers: Vec<HistoryContainer>,
}

// ---------------------------------------------------------------------------
// Minute accumulation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct MinuteAcc {
    n: u32,
    cgroup_id: u64,
    // Identity, from the last sample.
    pod_uid: String,
    pod_name: String,
    namespace: String,
    container: String,
    counters: Counters,
    usage_millis: GaugeAcc,
    cpu_some: GaugeAcc,
    cpu_full: GaugeAcc,
    mem_current: GaugeAcc,
    mem_ws: GaugeAcc,
    mem_some: GaugeAcc,
    mem_full: GaugeAcc,
    quota_usec: Option<u64>,
    period_usec: u64,
    request_millis: Option<u64>,
    limit_millis: Option<u64>,
    mem_limit: Option<u64>,
    mem_request: Option<u64>,
    hist: [u64; 24],
    has_runq: bool,
    blame: HashMap<u64, BlameEntry>,
}

impl MinuteAcc {
    fn push_cpu_mem(&mut self, cpu: &CpuSample, mem: &MemSample, interval_ms: u64) {
        self.n += 1;
        let c = &mut self.counters;
        c.usage_usec += cpu.usage_usec;
        c.nr_periods += cpu.nr_periods;
        c.nr_throttled += cpu.nr_throttled;
        c.throttled_usec += cpu.throttled_usec;
        c.events_high += mem.events_high;
        c.events_max += mem.events_max;
        c.oom_kill += mem.oom_kill;
        c.refault += mem.refault;
        c.pgmajfault += mem.pgmajfault;
        self.usage_millis
            .push(usage_millis(cpu.usage_usec, interval_ms));
        self.cpu_some.push(cpu.psi_some10);
        self.cpu_full.push(cpu.psi_full10);
        self.mem_current.push(mem.current as f64);
        self.mem_ws.push(mem.working_set as f64);
        self.mem_some.push(mem.psi_some10);
        self.mem_full.push(mem.psi_full10);
        self.quota_usec = cpu.quota_usec;
        self.period_usec = cpu.period_usec;
        self.request_millis = cpu.request_millis;
        self.limit_millis = cpu.limit_millis;
        self.mem_limit = mem.limit;
        self.mem_request = mem.request;
    }

    fn push_container(&mut self, s: &ContainerSample, interval_ms: u64) {
        self.cgroup_id = s.cgroup_id;
        self.pod_uid = s.pod_uid.clone();
        self.pod_name = s.pod_name.clone();
        self.namespace = s.namespace.clone();
        self.container = s.container.clone();
        self.push_cpu_mem(&s.cpu, &s.memory, interval_ms);
        if let Some(r) = &s.runq {
            self.has_runq = true;
            for (acc, v) in self.hist.iter_mut().zip(r.hist.iter()) {
                *acc += v;
            }
        }
        for b in &s.blame {
            let e = self.blame.entry(b.cgroup_id).or_insert_with(|| BlameEntry {
                count: 0,
                wait_ns: 0,
                ..b.clone()
            });
            e.count += b.count;
            e.wait_ns += b.wait_ns;
        }
    }

    fn cpu(&self) -> HistoryCpu {
        HistoryCpu {
            usage_usec: self.counters.usage_usec,
            usage_millis: self.usage_millis.gauge(),
            quota_usec: self.quota_usec,
            period_usec: self.period_usec,
            request_millis: self.request_millis,
            limit_millis: self.limit_millis,
            nr_periods: self.counters.nr_periods,
            nr_throttled: self.counters.nr_throttled,
            throttled_usec: self.counters.throttled_usec,
            psi_some10: self.cpu_some.gauge(),
            psi_full10: self.cpu_full.gauge(),
        }
    }

    fn memory(&self) -> HistoryMem {
        HistoryMem {
            current: self.mem_current.gauge(),
            working_set: self.mem_ws.gauge(),
            limit: self.mem_limit,
            request: self.mem_request,
            psi_some10: self.mem_some.gauge(),
            psi_full10: self.mem_full.gauge(),
            events_high: self.counters.events_high,
            events_max: self.counters.events_max,
            oom_kill: self.counters.oom_kill,
            refault: self.counters.refault,
            pgmajfault: self.counters.pgmajfault,
        }
    }

    fn into_container(self) -> HistoryContainer {
        let cpu = self.cpu();
        let memory = self.memory();
        let mut blame: Vec<BlameEntry> = self.blame.into_values().collect();
        blame.sort_by_key(|a| std::cmp::Reverse(a.wait_ns));
        blame.truncate(HISTORY_BLAME_LIMIT);
        HistoryContainer {
            container_uid: format!("{}/{}", self.pod_uid, self.container),
            pod_uid: self.pod_uid,
            pod_name: self.pod_name,
            namespace: self.namespace,
            container: self.container,
            cgroup_id: self.cgroup_id,
            samples: self.n,
            cpu,
            memory,
            runq: self.has_runq.then(|| RunqSample::from_hist(self.hist)),
            blame,
        }
    }
}

/// CPU usage as millicores over an interval: µs of CPU per ms of wall.
pub fn usage_millis(usage_usec: u64, interval_ms: u64) -> f64 {
    if interval_ms == 0 {
        return 0.0;
    }
    usage_usec as f64 / interval_ms as f64
}

/// Everything folded since the last history flush.
///
/// Closed by the sampler on the Nth sample (see [`fold_size`]), not by
/// wall clock, so a row labelled `resolution_secs: 60` always holds
/// exactly N samples and `interval_ms` is the sum of their intervals.
/// Ticks that produced no container rows are not pushed and do not
/// count.
#[derive(Debug, Default)]
pub struct MinuteFold {
    containers: HashMap<String, MinuteAcc>,
    /// Samples folded so far.
    ticks: u32,
    interval_ms: u64,
    ctxt: GaugeAcc,
    unknown_share: GaugeAcc,
}

impl MinuteFold {
    pub fn push(&mut self, batch: &ComputeBatch) {
        if batch.containers.is_empty() {
            return;
        }
        self.ticks += 1;
        self.interval_ms += batch.interval_ms;
        self.ctxt.push(batch.ctxt_per_sec);
        self.unknown_share.push(batch.unknown_blame_share);
        for c in &batch.containers {
            self.containers
                .entry(c.container_uid.clone())
                .or_default()
                .push_container(c, batch.interval_ms);
        }
    }

    pub fn ticks(&self) -> u32 {
        self.ticks
    }

    pub fn is_empty(&self) -> bool {
        self.containers.is_empty()
    }

    /// `n` samples have been folded: time to close the row.
    pub fn ready(&self, n: u32) -> bool {
        self.ticks >= n.max(1)
    }

    /// Reduce to a history envelope, taking the node-level fields from
    /// the latest sample batch.
    pub fn finish(self, latest: &ComputeBatch) -> HistoryBatch {
        let mut containers: Vec<HistoryContainer> = self
            .containers
            .into_values()
            .map(MinuteAcc::into_container)
            .collect();
        containers.sort_by(|a, b| a.container_uid.cmp(&b.container_uid));
        HistoryBatch {
            node: latest.node.clone(),
            ts: latest.ts.clone(),
            interval_ms: self.interval_ms,
            resolution_secs: HISTORY_INTERVAL.as_secs(),
            ctxt_per_sec: self.ctxt.gauge().avg,
            compute_enabled: latest.compute_enabled,
            compute_supported: latest.compute_supported,
            contention_loaded: latest.contention_loaded,
            node_pressure: latest.node_pressure.clone(),
            node_capacity: latest.node_capacity.clone(),
            bpf_occupancy: latest.bpf_occupancy.clone(),
            unknown_blame_share: self.unknown_share.gauge().avg,
            containers,
        }
    }
}

/// Split a batch into POSTs of at most `max` containers, each carrying
/// the full node envelope. An empty batch is one POST (the node row).
pub fn chunk_batch(batch: ComputeBatch, max: usize) -> Vec<ComputeBatch> {
    let max = max.max(1);
    if batch.containers.len() <= max {
        return vec![batch];
    }
    let ComputeBatch { containers, .. } = &batch;
    let mut out = Vec::with_capacity(containers.len().div_ceil(max));
    for chunk in containers.chunks(max) {
        out.push(ComputeBatch {
            containers: chunk.to_vec(),
            ..batch.clone()
        });
    }
    out
}

/// Same as [`chunk_batch`] for the history envelope.
pub fn chunk_history(batch: HistoryBatch, max: usize) -> Vec<HistoryBatch> {
    let max = max.max(1);
    if batch.containers.len() <= max {
        return vec![batch];
    }
    let HistoryBatch { containers, .. } = &batch;
    let mut out = Vec::with_capacity(containers.len().div_ceil(max));
    for chunk in containers.chunks(max) {
        out.push(HistoryBatch {
            containers: chunk.to_vec(),
            ..batch.clone()
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Culprit resolution
// ---------------------------------------------------------------------------

/// Classify a cgroup path that is not a tracked container.
///
/// | path | kind | ref |
/// |---|---|---|
/// | `kubepods…pod<uid>…` | `pod` | `pod:<uid8>` |
/// | `system.slice/<unit>`, `init.scope` | `system` | last two components |
/// | `` (root: kernel threads) | `kernel` | `kernel` |
/// | anything else | `unknown` | last two components |
pub fn classify_cgroup_path(path: &str) -> (&'static str, String) {
    let p = path.trim_matches('/');
    if p.is_empty() {
        return ("kernel", "kernel".to_string());
    }
    if p.starts_with("kubepods") {
        return match pod_uid_from_cgroup_path(p) {
            Some(uid8) => ("pod", format!("pod:{uid8}")),
            None => ("pod", last_two(p)),
        };
    }
    if p.starts_with("system.slice") || p == "init.scope" {
        return ("system", last_two(p));
    }
    ("unknown", last_two(p))
}

fn last_two(p: &str) -> String {
    let parts: Vec<&str> = p.rsplit('/').take(2).collect();
    parts.into_iter().rev().collect::<Vec<_>>().join("/")
}

/// The first 8 characters of the pod uid embedded in a kubepods path,
/// for either driver: `kubepods-burstable-pod3f2a…_….slice` (systemd
/// writes `_` for `-`) or `kubepods/burstable/pod3f2a…-…`.
pub fn pod_uid_from_cgroup_path(path: &str) -> Option<String> {
    for comp in path.split('/') {
        let c = comp.strip_suffix(".slice").unwrap_or(comp);
        let Some(idx) = c.rfind("pod") else { continue };
        let uid = &c[idx + 3..];
        let looks_like_uid = uid.len() >= 8
            && uid
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() || ch == '-' || ch == '_')
            && uid.chars().next().is_some_and(|ch| ch.is_ascii_hexdigit());
        if looks_like_uid {
            return Some(uid[..8].replace('_', "-"));
        }
    }
    None
}

/// id → relative path for every cgroup under `root`, bounded. The flag
/// says whether the bound cut the walk short (the caller logs that
/// once, not every 30 s).
pub fn build_cgroup_index(root: &Path, limit: usize) -> (HashMap<u64, String>, bool) {
    let mut index = HashMap::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut visited = 0usize;
    let mut truncated = false;
    while let Some(dir) = stack.pop() {
        if visited >= limit {
            truncated = true;
            break;
        }
        visited += 1;
        if let Ok(id) = cgroup_id_for_full_path(&dir) {
            let rel = dir
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            index.insert(id, rel);
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            // `file_type` on a cgroupfs entry does not follow anything
            // and is cheaper than a stat.
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                stack.push(e.path());
            }
        }
    }
    (index, truncated)
}

fn resolve_culprit(
    id: u64,
    registry: &ComputeMap,
    index: &HashMap<u64, String>,
    exited: &HashSet<u64>,
) -> (&'static str, String, Option<String>) {
    if let Some(c) = registry.lookup_cgroup(id) {
        return (
            "pod",
            format!("{}/{}/{}", c.namespace, c.pod_name, c.container_name),
            Some(c.container_uid()),
        );
    }
    // Opted-out pods (design D9): not sampled, not tracked, but still
    // named with their full identity when they are the bully.
    if let Some(c) = registry.lookup_identity(id) {
        return (
            "pod",
            format!("{}/{}/{}", c.namespace, c.pod_name, c.container_name),
            Some(c.container_uid()),
        );
    }
    if id == 0 {
        return ("kernel", "kernel".to_string(), None);
    }
    match index.get(&id) {
        Some(path) => {
            let (kind, r) = classify_cgroup_path(path);
            (kind, r, None)
        }
        // Judged after a rebuild and still absent: the cgroup exited.
        None if exited.contains(&id) => ("unknown", "exited".to_string(), None),
        // Not yet judged (rebuild rate-limited): unknown for now.
        None => ("unknown", format!("cgroup:{id}"), None),
    }
}

fn blame_for(
    pairs: &[PairDelta],
    registry: &ComputeMap,
    index: &HashMap<u64, String>,
    exited: &HashSet<u64>,
    limit: usize,
) -> Vec<BlameEntry> {
    let mut out: Vec<BlameEntry> = pairs
        .iter()
        .filter(|p| p.count > 0 || p.wait_ns > 0)
        .map(|p| {
            let (kind, reference, container_uid) =
                resolve_culprit(p.culprit_cgroup_id, registry, index, exited);
            BlameEntry {
                cgroup_id: p.culprit_cgroup_id,
                kind,
                reference,
                container_uid,
                count: p.count,
                wait_ns: p.wait_ns,
            }
        })
        .collect();
    out.sort_by_key(|a| std::cmp::Reverse(a.wait_ns));
    out.truncate(limit);
    out
}

/// Share of all blamed wait time attributed to `unknown` culprits.
pub fn unknown_blame_share(containers: &[ContainerSample]) -> f64 {
    let mut total = 0u128;
    let mut unknown = 0u128;
    for c in containers {
        for b in &c.blame {
            total += u128::from(b.wait_ns);
            if b.kind == "unknown" {
                unknown += u128::from(b.wait_ns);
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        unknown as f64 / total as f64
    }
}

// ---------------------------------------------------------------------------
// Sample assembly
// ---------------------------------------------------------------------------

fn cpu_sample(raw: &CgroupRaw, d: &Counters, res: &ResourceSpec) -> CpuSample {
    CpuSample {
        usage_usec: d.usage_usec,
        quota_usec: raw.cpu_max.quota_usec,
        period_usec: raw.cpu_max.period_usec,
        request_millis: res.cpu_request_millis,
        limit_millis: res.cpu_limit_millis,
        nr_periods: d.nr_periods,
        nr_throttled: d.nr_throttled,
        throttled_usec: d.throttled_usec,
        psi_some10: raw.cpu_psi.map(|p| p.some_avg10).unwrap_or(0.0),
        psi_full10: raw.cpu_psi.map(|p| p.full_avg10).unwrap_or(0.0),
    }
}

fn mem_sample(raw: &CgroupRaw, d: &Counters, res: &ResourceSpec) -> MemSample {
    MemSample {
        current: raw.mem_current,
        working_set: working_set(raw.mem_current, raw.mem_stat.inactive_file),
        limit: raw.mem_max.or(res.memory_limit_bytes),
        request: res.memory_request_bytes,
        psi_some10: raw.mem_psi.map(|p| p.some_avg10).unwrap_or(0.0),
        psi_full10: raw.mem_psi.map(|p| p.full_avg10).unwrap_or(0.0),
        events_high: d.events_high,
        events_max: d.events_max,
        oom_kill: d.oom_kill,
        refault: d.refault,
        pgmajfault: d.pgmajfault,
    }
}

/// Build one container's sample from its raw read and its counter delta.
/// Pure; the loop supplies the contention pieces.
pub fn container_sample(
    c: &ContainerCompute,
    raw: &CgroupRaw,
    delta: &Counters,
    runq: Option<RunqSample>,
    blame: Vec<BlameEntry>,
) -> ContainerSample {
    ContainerSample {
        container_uid: c.container_uid(),
        pod_uid: c.pod_uid.clone(),
        pod_name: c.pod_name.clone(),
        namespace: c.namespace.clone(),
        container: c.container_name.clone(),
        cgroup_id: c.cgroup_id,
        cpu: cpu_sample(raw, delta, &c.resources),
        memory: mem_sample(raw, delta, &c.resources),
        runq,
        blame,
    }
}

// ---------------------------------------------------------------------------
// The sampler
// ---------------------------------------------------------------------------

/// Node-level state carried between ticks.
#[derive(Debug, Clone, Copy)]
struct NodePrev {
    ctxt: u64,
    at: Instant,
}

/// One pending POST: the tick it came from, endpoint path and body.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingPost {
    pub tick: u64,
    pub path: &'static str,
    pub body: serde_json::Value,
}

/// Keep only the posts from the newest `keep_ticks` ticks, dropping the
/// oldest ticks first. Returns how many posts were dropped. Ticks are
/// monotonic, so the queue is ordered by tick.
pub fn cap_pending(pending: &mut VecDeque<PendingPost>, keep_ticks: usize) -> usize {
    let Some(newest) = pending.back().map(|p| p.tick) else {
        return 0;
    };
    let oldest_kept = newest.saturating_sub(keep_ticks.max(1) as u64 - 1);
    let before = pending.len();
    while pending.front().is_some_and(|p| p.tick < oldest_kept) {
        pending.pop_front();
    }
    before - pending.len()
}

/// The sampler's whole state. Lives in an `Arc<Mutex<_>>` so a tick that
/// panics inside `spawn_blocking` leaves the state (poisoned, recovered)
/// behind rather than dropping it with the task.
pub struct Sampler {
    cfg: ComputeConfig,
    node: String,
    registry: ComputeMap,
    probe: Option<Box<dyn ContentionSource>>,
    events: broadcast::Receiver<ComputeRegistration>,
    supported: bool,
    prev: HashMap<u64, Counters>,
    prev_node: Option<NodePrev>,
    last_tick: Option<Instant>,
    cgroup_index: HashMap<u64, String>,
    index_built: Option<Instant>,
    index_truncated_warned: bool,
    /// Tick counter, for the on-demand index rebuild rate limit.
    tick: u64,
    /// Tick of the last index rebuild of any kind.
    last_rebuild_tick: u64,
    /// On-demand rebuilds so far (observability + tests).
    pub(crate) ondemand_rebuilds: u64,
    /// Culprit ids still unresolved right after a rebuild: the cgroup is
    /// gone (a transient scope that exited within the tick). Reported as
    /// `unknown`/`exited` and never used to trigger another rebuild.
    /// Cleared on every periodic rebuild so a recycled id is re-judged.
    exited: HashSet<u64>,
    fold: MinuteFold,
    fold_every: u32,
    /// Set once the probe has been told about every id in the registry.
    tracked_synced: bool,
    /// The startup self-check has fired (it fires at most once).
    self_check_done: bool,
    /// Cumulative probe insert-failure counters as of the previous
    /// snapshot, so the wire carries the per-interval delta: a single
    /// burst of dropped inserts must not flag the node forever.
    prev_failures: (u64, u64),
}

impl Sampler {
    pub fn new(
        cfg: ComputeConfig,
        node: String,
        registry: ComputeMap,
        probe: Option<Box<dyn ContentionSource>>,
        events: broadcast::Receiver<ComputeRegistration>,
    ) -> Self {
        let supported = compute_supported(&cfg.cgroup_root, &cfg.host_proc);
        let fold_every = fold_size(cfg.sample_interval);
        Self {
            cfg,
            node,
            registry,
            probe,
            events,
            supported,
            prev: HashMap::new(),
            prev_node: None,
            last_tick: None,
            cgroup_index: HashMap::new(),
            index_built: None,
            index_truncated_warned: false,
            tick: 0,
            last_rebuild_tick: 0,
            ondemand_rebuilds: 0,
            exited: HashSet::new(),
            fold: MinuteFold::default(),
            fold_every,
            tracked_synced: false,
            self_check_done: false,
            prev_failures: (0, 0),
        }
    }

    pub fn contention_loaded(&self) -> bool {
        self.probe.is_some()
    }

    /// Occupancy for the wire: gauges as read, failure counters as the
    /// delta since the previous snapshot (the kernel counters are
    /// cumulative and never reset while the probe is loaded). A counter
    /// that went backwards means the probe was reloaded: re-baseline.
    fn occupancy_delta(&mut self, m: &MapOccupancy) -> BpfOccupancy {
        let mut occ = BpfOccupancy::from(m);
        let (hist, pair, next) = failure_deltas(self.prev_failures, m);
        occ.hist_update_failures = hist;
        occ.pair_update_failures = pair;
        self.prev_failures = next;
        occ
    }

    pub fn supported(&self) -> bool {
        self.supported
    }

    /// Apply registry events to the probe's `tracked_cgroups` map.
    ///
    /// On the first tick, and after the channel lags, the whole
    /// registry is tracked from a snapshot instead of replaying events:
    /// the channel is drained first so an `Added` that is also in the
    /// snapshot is not tracked twice, and `Removed`s are still applied
    /// because the snapshot cannot say what used to be there.
    fn sync_tracked(&mut self) {
        let Some(probe) = self.probe.as_ref() else {
            // Nothing to track into; keep the channel drained so it
            // cannot lag.
            while self.events.try_recv().is_ok() {}
            return;
        };
        let mut resync = !self.tracked_synced;
        let mut added = Vec::new();
        let mut removed = Vec::new();
        loop {
            match self.events.try_recv() {
                Ok(ComputeRegistration::Added { cgroup_id }) => added.push(cgroup_id),
                Ok(ComputeRegistration::Removed { cgroup_id }) => removed.push(cgroup_id),
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    warn!(
                        skipped = n,
                        "compute registration events lagged; resyncing tracked set"
                    );
                    resync = true;
                }
                Err(_) => break,
            }
        }
        for cgroup_id in removed {
            if let Err(e) = probe.untrack(cgroup_id) {
                debug!(cgroup_id, error = %e, "tracked_cgroups delete failed");
            }
        }
        let to_track: Vec<u64> = if resync {
            self.registry
                .containers()
                .iter()
                .map(|c| c.cgroup_id)
                .collect()
        } else {
            added
        };
        for cgroup_id in to_track {
            if let Err(e) = probe.track(cgroup_id) {
                warn!(cgroup_id, error = %e, "tracked_cgroups insert failed");
            }
        }
        if resync {
            self.tracked_synced = true;
        }
    }

    /// Rebuild the id → path index now. Returns nothing; the bound
    /// warning fires once per process, then drops to debug.
    fn rebuild_index(&mut self, why: &'static str) {
        let started = Instant::now();
        let (index, truncated) = build_cgroup_index(&self.cfg.cgroup_root, CGROUP_INDEX_LIMIT);
        self.cgroup_index = index;
        self.index_built = Some(started);
        self.last_rebuild_tick = self.tick;
        if truncated {
            if self.index_truncated_warned {
                debug!(
                    limit = CGROUP_INDEX_LIMIT,
                    "cgroup index walk hit its bound again"
                );
            } else {
                warn!(
                    limit = CGROUP_INDEX_LIMIT,
                    "cgroup index walk hit its bound; culprit resolution is partial \
                     (reported once; further hits at debug)"
                );
                self.index_truncated_warned = true;
            }
        }
        debug!(
            why,
            entries = self.cgroup_index.len(),
            took_ms = started.elapsed().as_millis(),
            "cgroup index rebuilt"
        );
    }

    /// Periodic rebuild; only while a probe is loaded, because nothing
    /// else reads it. Returns whether a rebuild happened this tick.
    fn refresh_index_if_due(&mut self) -> bool {
        if self.probe.is_none() {
            return false;
        }
        let due = self
            .index_built
            .map(|t| t.elapsed() >= CGROUP_INDEX_REFRESH)
            .unwrap_or(true);
        if due {
            self.rebuild_index("periodic");
            self.exited.clear();
        }
        due
    }

    /// Culprit ids this snapshot names that nothing can resolve: not a
    /// registered container in either tier, not the kernel, not in the
    /// index, and not already known to have exited.
    fn unresolved_culprits(&self, snapshot: &ContentionSnapshot) -> Vec<u64> {
        let mut ids: Vec<u64> = snapshot
            .per_victim
            .values()
            .flat_map(|v| v.pairs.iter().map(|p| p.culprit_cgroup_id))
            .filter(|id| {
                *id != 0
                    && !self.cgroup_index.contains_key(id)
                    && !self.exited.contains(id)
                    && self.registry.lookup_cgroup(*id).is_none()
                    && self.registry.lookup_identity(*id).is_none()
            })
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// After a rebuild, whatever is still unresolved is a cgroup that no
    /// longer exists: remember it so it is reported as `exited` and does
    /// not trigger another walk.
    fn mark_exited(&mut self, snapshot: &ContentionSnapshot) {
        for id in self.unresolved_culprits(snapshot) {
            self.exited.insert(id);
        }
    }

    /// Rebuild the index for a culprit the index does not know, at most
    /// once every [`ONDEMAND_REBUILD_EVERY_TICKS`] ticks. Ids that are
    /// still unknown afterwards are marked exited.
    fn resolve_unknown_culprits(&mut self, snapshot: &ContentionSnapshot, rebuilt_this_tick: bool) {
        if rebuilt_this_tick {
            self.mark_exited(snapshot);
            return;
        }
        if self.unresolved_culprits(snapshot).is_empty() {
            return;
        }
        if self.tick.saturating_sub(self.last_rebuild_tick) < ONDEMAND_REBUILD_EVERY_TICKS {
            // Rate-limited: this tick reports them as `cgroup:<id>`
            // (unknown, not yet judged) and tries again later.
            return;
        }
        self.rebuild_index("unresolved culprit");
        self.ondemand_rebuilds += 1;
        self.mark_exited(snapshot);
    }

    /// Once, three sample intervals after the watcher first saw an
    /// eligible pod: if nothing has been registered by then, the
    /// resolution path is broken on this node and the operator must be
    /// told at ERROR, not left with an empty UI and debug logs.
    fn startup_self_check(&mut self) {
        if self.self_check_done {
            return;
        }
        let Some(first) = self.registry.first_eligible_at() else {
            return;
        };
        if first.elapsed() < self.cfg.sample_interval * 3 {
            return;
        }
        self.self_check_done = true;
        if self.registry.resolved_containers() == 0 && self.registry.eligible_pods_seen() > 0 {
            tracing::error!(
                eligible_pods_seen = self.registry.eligible_pods_seen(),
                cgroup_root = %self.cfg.cgroup_root.display(),
                "compute: the pod watcher has seen eligible pods but no container cgroup could be \
                 resolved, so nothing is sampled. Check that {} is the HOST cgroup v2 root \
                 (chart mounts /sys/fs/cgroup read-only when compute.enabled), that containerd's \
                 Containers.Get is reachable on CONTAINERD_SOCK, and the per-container WARN lines \
                 from the pod watcher (\"could not resolve container cgroup\") for what each route saw.",
                self.cfg.cgroup_root.display()
            );
        }
    }

    fn read_node(&mut self, now: Instant) -> (NodePressure, NodeCapacity, f64) {
        let proc_ = &self.cfg.host_proc;
        let cpu_psi = read_opt(proc_, "pressure/cpu").and_then(|b| parse_pressure(&b));
        let mem_psi = read_opt(proc_, "pressure/memory").and_then(|b| parse_pressure(&b));
        let stat = read_opt(proc_, "stat")
            .map(|b| parse_proc_stat(&b))
            .unwrap_or_default();
        let memory_bytes = read_opt(proc_, "meminfo")
            .and_then(|b| parse_meminfo_total_bytes(&b))
            .unwrap_or(0);
        let ctxt_per_sec = match self.prev_node {
            Some(prev) if stat.ctxt >= prev.ctxt => {
                let secs = now.duration_since(prev.at).as_secs_f64();
                if secs > 0.0 {
                    (stat.ctxt - prev.ctxt) as f64 / secs
                } else {
                    0.0
                }
            }
            _ => 0.0,
        };
        self.prev_node = Some(NodePrev {
            ctxt: stat.ctxt,
            at: now,
        });
        (
            NodePressure {
                cpu_some10: cpu_psi.map(|p| p.some_avg10).unwrap_or(0.0),
                cpu_full10: cpu_psi.map(|p| p.full_avg10).unwrap_or(0.0),
                mem_some10: mem_psi.map(|p| p.some_avg10).unwrap_or(0.0),
                mem_full10: mem_psi.map(|p| p.full_avg10).unwrap_or(0.0),
            },
            NodeCapacity {
                cpu_cores: stat.cpus,
                memory_bytes,
            },
            ctxt_per_sec,
        )
    }

    /// Read a cgroup and return its raw contents plus the delta against
    /// the previous tick, or `None` on the first sighting / on a reset.
    fn read_with_delta(&mut self, cgroup_id: u64, rel: &str) -> Option<(CgroupRaw, Counters)> {
        let dir = self.cfg.cgroup_root.join(rel);
        let raw = match read_cgroup(&dir) {
            Ok(r) => r,
            Err(e) => {
                debug!(cgroup = rel, error = %e, "cgroup read failed (gone?)");
                return None;
            }
        };
        let cur = Counters::from_raw(&raw);
        let delta = self
            .prev
            .insert(cgroup_id, cur)
            .and_then(|prev| Counters::delta(&prev, &cur));
        delta.map(|d| (raw, d))
    }

    /// One tick: read everything, build the sample batch and, when the
    /// fold is full, the history batch. Synchronous IO — call from
    /// `spawn_blocking`.
    pub fn collect(&mut self) -> (ComputeBatch, Option<HistoryBatch>) {
        let now = Instant::now();
        let interval_ms = self
            .last_tick
            .map(|t| now.duration_since(t).as_millis() as u64)
            .filter(|ms| *ms > 0)
            .unwrap_or(self.cfg.sample_interval.as_millis() as u64);
        self.last_tick = Some(now);
        self.tick += 1;

        self.sync_tracked();
        let index_rebuilt = self.refresh_index_if_due();

        let (node_pressure, node_capacity, ctxt_per_sec) = self.read_node(now);

        // A failed snapshot is not "no wait": this tick ships `runq:
        // null` and says contention_loaded=false rather than a row of
        // zeros that reads as a healthy scheduler.
        let mut snapshot_failed = false;
        let snapshot = match self.probe.as_mut() {
            Some(p) => match p.snapshot() {
                Ok(s) => Some(s),
                Err(e) => {
                    warn!(error = %e, "contention snapshot failed; this sample carries no runq/blame");
                    snapshot_failed = true;
                    None
                }
            },
            None => None,
        };
        let contention_loaded = self.probe.is_some() && !snapshot_failed;
        if let Some(snap) = &snapshot {
            self.resolve_unknown_culprits(snap, index_rebuilt);
        }

        let mut seen: HashSet<u64> = HashSet::new();
        let mut containers = Vec::new();

        if self.supported {
            let registered = self.registry.containers();
            for c in &registered {
                seen.insert(c.cgroup_id);
                let Some((raw, delta)) = self.read_with_delta(c.cgroup_id, &c.cgroup_path) else {
                    continue;
                };
                let (runq, blame) = match &snapshot {
                    Some(s) => {
                        let victim = s.per_victim.get(&c.cgroup_id);
                        let hist = victim.map(|v| v.hist_delta).unwrap_or([0; 24]);
                        let blame = victim
                            .map(|v| {
                                blame_for(
                                    &v.pairs,
                                    &self.registry,
                                    &self.cgroup_index,
                                    &self.exited,
                                    SAMPLE_BLAME_LIMIT,
                                )
                            })
                            .unwrap_or_default();
                        (Some(RunqSample::from_hist(hist)), blame)
                    }
                    None => (None, Vec::new()),
                };
                containers.push(container_sample(c, &raw, &delta, runq, blame));
            }
        }
        // Forget counters for cgroups that are no longer registered.
        self.prev.retain(|id, _| seen.contains(id));

        containers.sort_by(|a, b| a.container_uid.cmp(&b.container_uid));
        let unknown_share = unknown_blame_share(&containers);
        let batch = ComputeBatch {
            node: self.node.clone(),
            ts: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            interval_ms,
            ctxt_per_sec,
            compute_enabled: self.cfg.enabled,
            compute_supported: self.supported,
            contention_loaded,
            node_pressure,
            node_capacity,
            bpf_occupancy: snapshot
                .as_ref()
                .map(|s| self.occupancy_delta(&s.map_occupancy))
                .unwrap_or_default(),
            unknown_blame_share: unknown_share,
            containers,
        };

        self.startup_self_check();

        self.fold.push(&batch);
        let history = if self.fold.ready(self.fold_every) {
            let fold = std::mem::take(&mut self.fold);
            Some(fold.finish(&batch))
        } else {
            None
        };
        (batch, history)
    }
}

/// Node-level pressure and capacity from host `/proc`, no state. The
/// sampler's per-tick path also tracks the context-switch rate; this is
/// the static subset the disabled heartbeat can afford.
pub fn read_node_static(host_proc: &Path) -> (NodePressure, NodeCapacity) {
    let cpu_psi = read_opt(host_proc, "pressure/cpu").and_then(|b| parse_pressure(&b));
    let mem_psi = read_opt(host_proc, "pressure/memory").and_then(|b| parse_pressure(&b));
    let stat = read_opt(host_proc, "stat")
        .map(|b| parse_proc_stat(&b))
        .unwrap_or_default();
    let memory_bytes = read_opt(host_proc, "meminfo")
        .and_then(|b| parse_meminfo_total_bytes(&b))
        .unwrap_or(0);
    (
        NodePressure {
            cpu_some10: cpu_psi.map(|p| p.some_avg10).unwrap_or(0.0),
            cpu_full10: cpu_psi.map(|p| p.full_avg10).unwrap_or(0.0),
            mem_some10: mem_psi.map(|p| p.some_avg10).unwrap_or(0.0),
            mem_full10: mem_psi.map(|p| p.full_avg10).unwrap_or(0.0),
        },
        NodeCapacity {
            cpu_cores: stat.cpus,
            memory_bytes,
        },
    )
}

/// Cadence of the disabled heartbeat.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(300);

/// The node-only envelope a controller with `COMPUTE_ENABLED=false`
/// posts (design D10): it makes the UI's `off` state reachable, so a
/// node whose operator switched the feature off can be told apart from
/// a node running a controller older than the feature (which posts
/// nothing). No registry, no sampler, no cgroup files are read —
/// `compute_supported` is the same existence check node facts use.
pub fn disabled_heartbeat(cfg: &ComputeConfig, node: &str) -> ComputeBatch {
    let (node_pressure, node_capacity) = read_node_static(&cfg.host_proc);
    ComputeBatch {
        node: node.to_string(),
        ts: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        interval_ms: HEARTBEAT_INTERVAL.as_millis() as u64,
        ctxt_per_sec: 0.0,
        compute_enabled: false,
        compute_supported: compute_supported(&cfg.cgroup_root, &cfg.host_proc),
        contention_loaded: false,
        node_pressure,
        node_capacity,
        bpf_occupancy: BpfOccupancy::default(),
        unknown_blame_share: 0.0,
        containers: Vec::new(),
    }
}

/// The `compute-sampler` subsystem when the feature is OFF: post the
/// disabled heartbeat at startup and every five minutes. Best-effort;
/// a failed POST is logged at debug and retried next time.
pub async fn run_heartbeat(cfg: ComputeConfig, node: String) -> Result<(), Error> {
    info!(
        interval_secs = HEARTBEAT_INTERVAL.as_secs(),
        "compute sampler disabled (COMPUTE_ENABLED=false); posting a node-only heartbeat"
    );
    let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let batch = disabled_heartbeat(&cfg, &node);
        if let Err(e) = api_post_call(
            serde_json::to_value(&batch).unwrap_or_default(),
            SAMPLE_PATH,
        )
        .await
        {
            debug!(error = %e, "compute heartbeat POST failed; retrying next interval");
        }
    }
}

/// cgroup v2 root with PSI available.
pub fn compute_supported(cgroup_root: &Path, host_proc: &Path) -> bool {
    cgroup_root.join("cgroup.controllers").exists() && host_proc.join("pressure/cpu").exists()
}

/// Post every pending batch in order; stop at the first failure and
/// hold the rest. Returns the number dropped by the cap.
async fn flush_pending(pending: &mut VecDeque<PendingPost>) -> usize {
    while let Some((path, body)) = pending.front().map(|p| (p.path, p.body.clone())) {
        match api_post_call(body, path).await {
            Ok(()) => {
                pending.pop_front();
            }
            Err(e) => {
                warn!(
                    path,
                    pending = pending.len(),
                    error = %e,
                    "compute batch POST failed; holding for retry next tick"
                );
                break;
            }
        }
    }
    let dropped = cap_pending(pending, MAX_PENDING_TICKS);
    if dropped > 0 {
        warn!(
            dropped,
            keep_ticks = MAX_PENDING_TICKS,
            "compute pending queue overflow during broker outage; dropped oldest batches"
        );
    }
    dropped
}

/// The `compute-sampler` subsystem. Returns `Ok(())` immediately when
/// the feature is off (`MayRetire`); otherwise runs until the process
/// does.
///
/// A panic inside a tick is logged at ERROR and the tick skipped. The
/// alternative — letting the `JoinError` propagate — ends the whole
/// controller, traffic capture included, for a bug in an optional
/// gauge; a `MayRetire` subsystem must not take capture down.
pub async fn run(
    cfg: ComputeConfig,
    node: String,
    registry: ComputeMap,
    probe: Option<Box<dyn ContentionSource>>,
    events: broadcast::Receiver<ComputeRegistration>,
) -> Result<(), Error> {
    if !cfg.enabled {
        info!("compute sampler disabled (COMPUTE_ENABLED=false)");
        return Ok(());
    }
    let interval = cfg.sample_interval;
    let sampler = Sampler::new(cfg, node, registry, probe, events);
    info!(
        interval_secs = interval.as_secs(),
        supported = sampler.supported(),
        contention_loaded = sampler.contention_loaded(),
        fold_every = sampler.fold_every,
        "compute sampler started"
    );
    if !sampler.supported() {
        warn!(
            "compute gauges unsupported on this node (needs cgroup v2 and PSI); \
             node samples will report compute_supported=false"
        );
    }
    let sampler = std::sync::Arc::new(std::sync::Mutex::new(sampler));

    let mut pending: VecDeque<PendingPost> = VecDeque::new();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut tick: u64 = 0;
    // The first tick fires immediately; it seeds the counters and posts
    // a node envelope so the broker learns the node is on.
    loop {
        ticker.tick().await;
        tick += 1;
        let state = std::sync::Arc::clone(&sampler);
        let joined = tokio::task::spawn_blocking(move || {
            // A poisoned mutex is a previous tick's panic; the state is
            // still the best one available, so recover it.
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.collect()
        })
        .await;
        let (batch, history) = match joined {
            Ok(v) => v,
            Err(e) if e.is_panic() => {
                tracing::error!(
                    error = %e,
                    "compute sampler tick panicked; skipping this sample and continuing"
                );
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        debug!(
            containers = batch.containers.len(),
            interval_ms = batch.interval_ms,
            history = history.is_some(),
            "compute sample collected"
        );
        for chunk in chunk_batch(batch, MAX_CONTAINERS_PER_POST) {
            pending.push_back(PendingPost {
                tick,
                path: SAMPLE_PATH,
                body: serde_json::to_value(&chunk).unwrap_or_default(),
            });
        }
        if let Some(h) = history {
            for chunk in chunk_history(h, MAX_CONTAINERS_PER_POST) {
                pending.push_back(PendingPost {
                    tick,
                    path: HISTORY_PATH,
                    body: serde_json::to_value(&chunk).unwrap_or_default(),
                });
            }
        }
        flush_pending(&mut pending).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_registry::ComputeRegistry;
    use crate::contention::VictimStats;
    use std::sync::Arc;

    // ---- fixture strings captured from a cgroup v2 node ----

    const CPU_STAT_THROTTLED: &str = "usage_usec 4120335\n\
        user_usec 3100000\n\
        system_usec 1020335\n\
        core_sched.force_idle_usec 0\n\
        nr_periods 500\n\
        nr_throttled 42\n\
        throttled_usec 810000\n\
        nr_bursts 0\n\
        burst_usec 0\n";

    const CPU_MAX_UNLIMITED: &str = "max 100000\n";
    const CPU_MAX_HALF: &str = "50000 100000\n";

    const CPU_PRESSURE: &str = "some avg10=12.40 avg60=8.11 avg300=3.02 total=91827364\n\
        full avg10=0.80 avg60=0.40 avg300=0.10 total=1234567\n";

    const MEMORY_STAT: &str = "anon 150994944\n\
        file 32505856\n\
        kernel 4194304\n\
        kernel_stack 262144\n\
        shmem 0\n\
        file_mapped 8388608\n\
        inactive_anon 0\n\
        active_anon 150994944\n\
        inactive_file 12500000\n\
        active_file 20005856\n\
        workingset_refault_anon 20\n\
        workingset_refault_file 100\n\
        workingset_activate_anon 0\n\
        pgfault 123456\n\
        pgmajfault 7\n";

    const MEMORY_EVENTS: &str = "low 0\nhigh 3\nmax 1\noom 0\noom_kill 0\noom_group_kill 0\n";

    const PROC_STAT: &str = "cpu  1 2 3 4 5 6 7 0 0 0\n\
        cpu0 1 2 3 4 5 6 7 0 0 0\n\
        cpu1 1 2 3 4 5 6 7 0 0 0\n\
        cpu2 1 2 3 4 5 6 7 0 0 0\n\
        cpu3 1 2 3 4 5 6 7 0 0 0\n\
        intr 1 2 3\n\
        ctxt 987654321\n\
        btime 1700000000\n\
        processes 1234\n";

    const MEMINFO: &str = "MemTotal:       32768000 kB\nMemFree:        1000 kB\n";

    #[test]
    fn cpu_stat_parses_throttle_counters() {
        let s = parse_cpu_stat(CPU_STAT_THROTTLED);
        assert_eq!(
            s,
            CpuStat {
                usage_usec: 4_120_335,
                user_usec: 3_100_000,
                system_usec: 1_020_335,
                nr_periods: 500,
                nr_throttled: 42,
                throttled_usec: 810_000,
            }
        );
        // No throttle lines at all (cpu controller without a quota ever set).
        let s = parse_cpu_stat("usage_usec 10\nuser_usec 5\nsystem_usec 5\n");
        assert_eq!(s.usage_usec, 10);
        assert_eq!(s.nr_periods, 0);
    }

    #[test]
    fn cpu_max_distinguishes_unlimited_from_quota() {
        assert_eq!(
            parse_cpu_max(CPU_MAX_UNLIMITED),
            CpuMax {
                quota_usec: None,
                period_usec: 100_000
            }
        );
        assert_eq!(
            parse_cpu_max(CPU_MAX_HALF),
            CpuMax {
                quota_usec: Some(50_000),
                period_usec: 100_000
            }
        );
        assert_eq!(parse_cpu_max(""), CpuMax::default());
    }

    #[test]
    fn psi_some_and_full_lines_parse() {
        let p = parse_pressure(CPU_PRESSURE).unwrap();
        assert!((p.some_avg10 - 12.4).abs() < 1e-9);
        assert!((p.some_avg60 - 8.11).abs() < 1e-9);
        assert_eq!(p.some_total, 91_827_364);
        assert!((p.full_avg10 - 0.8).abs() < 1e-9);
        assert_eq!(p.full_total, 1_234_567);
        // `/proc/pressure/cpu` on older kernels has only `some`.
        let p = parse_pressure("some avg10=3.10 avg60=1.00 avg300=0.50 total=42\n").unwrap();
        assert!((p.some_avg10 - 3.1).abs() < 1e-9);
        assert_eq!(p.full_avg10, 0.0);
        assert_eq!(parse_pressure("not psi\n"), None);
    }

    #[test]
    fn memory_stat_and_events_parse_and_working_set_floors_at_zero() {
        let m = parse_memory_stat(MEMORY_STAT);
        assert_eq!(m.anon, 150_994_944);
        assert_eq!(m.file, 32_505_856);
        assert_eq!(m.inactive_file, 12_500_000);
        assert_eq!(m.workingset_refault_anon, 20);
        assert_eq!(m.workingset_refault_file, 100);
        assert_eq!(m.pgmajfault, 7);
        let e = parse_memory_events(MEMORY_EVENTS);
        assert_eq!(
            e,
            MemEvents {
                low: 0,
                high: 3,
                max: 1,
                oom: 0,
                oom_kill: 0
            }
        );
        assert_eq!(working_set(183_500_800, 12_500_000), 171_000_800);
        assert_eq!(working_set(10, 20), 0);
        assert_eq!(parse_u64_or_max("max\n"), None);
        assert_eq!(parse_u64_or_max("268435456\n"), Some(268_435_456));
    }

    #[test]
    fn proc_stat_and_meminfo_parse() {
        let s = parse_proc_stat(PROC_STAT);
        assert_eq!(
            s,
            ProcStat {
                ctxt: 987_654_321,
                cpus: 4
            }
        );
        assert_eq!(parse_meminfo_total_bytes(MEMINFO), Some(32_768_000 * 1024));
        assert_eq!(parse_meminfo_total_bytes("MemFree: 1 kB\n"), None);
    }

    #[test]
    fn counter_deltas_and_reset_detection() {
        let prev = Counters {
            usage_usec: 100,
            nr_periods: 10,
            nr_throttled: 1,
            throttled_usec: 5,
            events_high: 0,
            events_max: 0,
            oom_kill: 0,
            refault: 3,
            pgmajfault: 1,
        };
        let cur = Counters {
            usage_usec: 412_100,
            nr_periods: 60,
            nr_throttled: 3,
            throttled_usec: 8_105,
            events_high: 2,
            events_max: 0,
            oom_kill: 0,
            refault: 123,
            pgmajfault: 1,
        };
        let d = Counters::delta(&prev, &cur).unwrap();
        assert_eq!(d.usage_usec, 412_000);
        assert_eq!(d.nr_periods, 50);
        assert_eq!(d.nr_throttled, 2);
        assert_eq!(d.throttled_usec, 8_100);
        assert_eq!(d.events_high, 2);
        assert_eq!(d.refault, 120);
        assert_eq!(d.pgmajfault, 0);
        assert!(
            Counters::delta(&cur, &prev).is_none(),
            "backwards counter is a reset"
        );
    }

    #[test]
    fn read_cgroup_from_a_fixture_directory() {
        let dir = std::env::temp_dir().join(format!("kg-compute-cg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cpu.stat"), CPU_STAT_THROTTLED).unwrap();
        std::fs::write(dir.join("cpu.max"), CPU_MAX_HALF).unwrap();
        std::fs::write(dir.join("cpu.pressure"), CPU_PRESSURE).unwrap();
        std::fs::write(dir.join("memory.current"), "183500800\n").unwrap();
        std::fs::write(dir.join("memory.max"), "268435456\n").unwrap();
        std::fs::write(dir.join("memory.stat"), MEMORY_STAT).unwrap();
        std::fs::write(dir.join("memory.pressure"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
        std::fs::write(dir.join("memory.events"), MEMORY_EVENTS).unwrap();
        let raw = read_cgroup(&dir).unwrap();
        assert_eq!(raw.cpu.usage_usec, 4_120_335);
        assert_eq!(raw.cpu_max.quota_usec, Some(50_000));
        assert_eq!(raw.mem_current, 183_500_800);
        assert_eq!(raw.mem_max, Some(268_435_456));
        assert_eq!(raw.mem_stat.inactive_file, 12_500_000);
        assert_eq!(raw.mem_events.high, 3);
        assert!(raw.cpu_psi.is_some());
        let c = Counters::from_raw(&raw);
        assert_eq!(c.refault, 120);
        // A directory with no cpu.stat is not a cgroup.
        std::fs::remove_file(dir.join("cpu.stat")).unwrap();
        assert!(read_cgroup(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cgroup_paths_classify_per_the_design_table() {
        assert_eq!(
            classify_cgroup_path(
                "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3f2a9c1e_7b4d_4e0a_9f1c_0123456789ab.slice/cri-containerd-abc.scope"
            ),
            ("pod", "pod:3f2a9c1e".to_string())
        );
        assert_eq!(
            classify_cgroup_path("kubepods/besteffort/pod3f2a9c1e-7b4d-4e0a-9f1c-0123456789ab/abc"),
            ("pod", "pod:3f2a9c1e".to_string())
        );
        assert_eq!(
            classify_cgroup_path("system.slice/kubelet.service"),
            ("system", "system.slice/kubelet.service".to_string())
        );
        assert_eq!(
            classify_cgroup_path("system.slice/system-getty.slice/getty@tty1.service"),
            (
                "system",
                "system-getty.slice/getty@tty1.service".to_string()
            )
        );
        assert_eq!(
            classify_cgroup_path("init.scope"),
            ("system", "init.scope".to_string())
        );
        assert_eq!(classify_cgroup_path(""), ("kernel", "kernel".to_string()));
        assert_eq!(classify_cgroup_path("/"), ("kernel", "kernel".to_string()));
        assert_eq!(
            classify_cgroup_path("user.slice/user-1000.slice/session-3.scope"),
            ("unknown", "user-1000.slice/session-3.scope".to_string())
        );
        // `kubepods` itself contains "pod" — must not be mistaken for a uid.
        assert_eq!(
            pod_uid_from_cgroup_path("kubepods.slice/kubepods-burstable.slice"),
            None
        );
    }

    #[test]
    fn unknown_blame_share_is_a_wait_time_ratio() {
        let mk = |kind: &'static str, wait_ns: u64| BlameEntry {
            cgroup_id: 1,
            kind,
            reference: String::new(),
            container_uid: None,
            count: 1,
            wait_ns,
        };
        let c = |blame: Vec<BlameEntry>| ContainerSample {
            container_uid: "u/c".into(),
            pod_uid: "u".into(),
            pod_name: "p".into(),
            namespace: "n".into(),
            container: "c".into(),
            cgroup_id: 5,
            cpu: CpuSample {
                usage_usec: 0,
                quota_usec: None,
                period_usec: 100_000,
                request_millis: None,
                limit_millis: None,
                nr_periods: 0,
                nr_throttled: 0,
                throttled_usec: 0,
                psi_some10: 0.0,
                psi_full10: 0.0,
            },
            memory: MemSample {
                current: 0,
                working_set: 0,
                limit: None,
                request: None,
                psi_some10: 0.0,
                psi_full10: 0.0,
                events_high: 0,
                events_max: 0,
                oom_kill: 0,
                refault: 0,
                pgmajfault: 0,
            },
            runq: None,
            blame,
        };
        assert_eq!(unknown_blame_share(&[]), 0.0);
        let s = unknown_blame_share(&[
            c(vec![mk("pod", 300), mk("unknown", 100)]),
            c(vec![mk("system", 100), mk("unknown", 300)]),
        ]);
        assert!((s - 0.5).abs() < 1e-12);
    }

    #[test]
    fn cap_pending_keeps_the_newest_ticks_whatever_their_chunk_count() {
        let post = |tick: u64| PendingPost {
            tick,
            path: SAMPLE_PATH,
            body: serde_json::json!(tick),
        };
        // 30 ticks, two chunks each (a 300-container node).
        let mut q: VecDeque<PendingPost> = (1..=30).flat_map(|t| [post(t), post(t)]).collect();
        assert_eq!(cap_pending(&mut q, 30), 0);
        assert_eq!(cap_pending(&mut q, 24), 12, "ticks 1..=6, two chunks each");
        assert_eq!(q.front().unwrap().tick, 7);
        assert_eq!(q.back().unwrap().tick, 30);
        assert_eq!(q.len(), 48);
        assert_eq!(cap_pending(&mut q, 1), 46);
        assert_eq!(q.len(), 2);
        let mut empty = VecDeque::new();
        assert_eq!(cap_pending(&mut empty, 24), 0);
    }

    #[test]
    fn minute_fold_reduces_gauges_and_sums_counters() {
        let cont = ContainerCompute {
            pod_uid: "u".into(),
            namespace: "payments".into(),
            pod_name: "api".into(),
            container_name: "api".into(),
            container_id: "x".into(),
            pid: 1,
            cgroup_path: "x".into(),
            cgroup_id: 18944,
            resources: ResourceSpec {
                cpu_request_millis: Some(250),
                cpu_limit_millis: Some(500),
                memory_request_bytes: None,
                memory_limit_bytes: None,
            },
            node: "n".into(),
        };
        let raw = |current: u64, psi: f64| CgroupRaw {
            cpu_max: CpuMax {
                quota_usec: Some(50_000),
                period_usec: 100_000,
            },
            cpu_psi: Some(Pressure {
                some_avg10: psi,
                ..Default::default()
            }),
            mem_current: current,
            ..Default::default()
        };
        let delta = |usage: u64| Counters {
            usage_usec: usage,
            nr_periods: 50,
            ..Default::default()
        };
        let node = |c: ContainerSample, blame_share: f64| ComputeBatch {
            node: "n".into(),
            ts: "t".into(),
            interval_ms: 5000,
            ctxt_per_sec: 100.0,
            compute_enabled: true,
            compute_supported: true,
            contention_loaded: true,
            node_pressure: NodePressure {
                cpu_some10: 0.0,
                cpu_full10: 0.0,
                mem_some10: 0.0,
                mem_full10: 0.0,
            },
            node_capacity: NodeCapacity {
                cpu_cores: 4,
                memory_bytes: 1,
            },
            bpf_occupancy: BpfOccupancy::default(),
            unknown_blame_share: blame_share,
            containers: vec![c],
        };
        let mut hist_a = [0u64; 24];
        hist_a[7] = 10;
        let blame_a = vec![BlameEntry {
            cgroup_id: 21003,
            kind: "pod",
            reference: "batch/etl/worker".into(),
            container_uid: Some("v/worker".into()),
            count: 210,
            wait_ns: 6_100_000_000,
        }];
        let mut hist_b = [0u64; 24];
        hist_b[7] = 5;
        hist_b[23] = 1;
        let blame_b = vec![
            BlameEntry {
                cgroup_id: 21003,
                kind: "pod",
                reference: "batch/etl/worker".into(),
                container_uid: Some("v/worker".into()),
                count: 10,
                wait_ns: 100,
            },
            BlameEntry {
                cgroup_id: 77,
                kind: "system",
                reference: "system.slice/kubelet.service".into(),
                container_uid: None,
                count: 40,
                wait_ns: 300_000_000,
            },
        ];
        let a = container_sample(
            &cont,
            &raw(100, 10.0),
            &delta(1_000_000),
            Some(RunqSample::from_hist(hist_a)),
            blame_a,
        );
        let b = container_sample(
            &cont,
            &raw(300, 30.0),
            &delta(2_000_000),
            Some(RunqSample::from_hist(hist_b)),
            blame_b,
        );
        let ba = node(a, 0.0);
        let bb = node(b, 1.0);
        let mut fold = MinuteFold::default();
        fold.push(&ba);
        fold.push(&bb);
        let h = fold.finish(&bb);
        assert_eq!(h.interval_ms, 10_000);
        assert_eq!(h.resolution_secs, 60);
        assert!((h.unknown_blame_share - 0.5).abs() < 1e-12);
        assert_eq!(h.containers.len(), 1);
        let c = &h.containers[0];
        assert_eq!(c.container_uid, "u/api");
        assert_eq!(c.samples, 2);
        assert_eq!(c.cpu.usage_usec, 3_000_000);
        assert_eq!(c.cpu.nr_periods, 100);
        // 1_000_000 µs / 5000 ms = 200 millicores; 2_000_000 → 400.
        assert_eq!(
            c.cpu.usage_millis,
            Gauge {
                avg: 300.0,
                max: 400.0,
                last: 400.0
            }
        );
        assert_eq!(
            c.cpu.psi_some10,
            Gauge {
                avg: 20.0,
                max: 30.0,
                last: 30.0
            }
        );
        assert_eq!(
            c.memory.current,
            Gauge {
                avg: 200.0,
                max: 300.0,
                last: 300.0
            }
        );
        assert_eq!(c.cpu.limit_millis, Some(500));
        let r = c.runq.as_ref().unwrap();
        assert_eq!(r.hist[7], 15);
        assert_eq!(r.hist[23], 1);
        assert_eq!(r.overflow, 1);
        assert_eq!(c.blame.len(), 2);
        assert_eq!(c.blame[0].cgroup_id, 21003);
        assert_eq!(c.blame[0].count, 220);
        assert_eq!(c.blame[0].wait_ns, 6_100_000_100);
        assert_eq!(c.blame[1].kind, "system");
    }

    fn empty_batch(interval_ms: u64) -> ComputeBatch {
        ComputeBatch {
            node: "n".into(),
            ts: "t".into(),
            interval_ms,
            ctxt_per_sec: 0.0,
            compute_enabled: true,
            compute_supported: true,
            contention_loaded: false,
            node_pressure: NodePressure {
                cpu_some10: 0.0,
                cpu_full10: 0.0,
                mem_some10: 0.0,
                mem_full10: 0.0,
            },
            node_capacity: NodeCapacity {
                cpu_cores: 1,
                memory_bytes: 1,
            },
            bpf_occupancy: BpfOccupancy::default(),
            unknown_blame_share: 0.0,
            containers: vec![],
        }
    }

    fn one_container_batch(interval_ms: u64) -> ComputeBatch {
        let cont = ContainerCompute {
            pod_uid: "u".into(),
            namespace: "n".into(),
            pod_name: "p".into(),
            container_name: "c".into(),
            container_id: "x".into(),
            pid: 1,
            cgroup_path: "x".into(),
            cgroup_id: 1,
            resources: ResourceSpec::default(),
            node: "n".into(),
        };
        let mut b = empty_batch(interval_ms);
        b.containers = vec![container_sample(
            &cont,
            &CgroupRaw::default(),
            &Counters {
                usage_usec: 1_000,
                ..Default::default()
            },
            None,
            vec![],
        )];
        b
    }

    #[test]
    fn fold_size_is_sixty_seconds_of_samples() {
        assert_eq!(fold_size(Duration::from_secs(5)), 12);
        assert_eq!(fold_size(Duration::from_secs(10)), 6);
        assert_eq!(fold_size(Duration::from_secs(1)), 60);
        assert_eq!(fold_size(Duration::from_secs(90)), 1, "never zero");
    }

    #[test]
    fn fold_closes_on_the_nth_sample_and_ignores_empty_ticks() {
        for (interval_s, n) in [(5u64, 12u32), (10, 6)] {
            let n_cfg = fold_size(Duration::from_secs(interval_s));
            assert_eq!(n_cfg, n);
            let mut fold = MinuteFold::default();
            // The empty t=0 seed batch must not count.
            fold.push(&empty_batch(interval_s * 1000));
            assert_eq!(fold.ticks(), 0);
            for k in 1..n {
                fold.push(&one_container_batch(interval_s * 1000));
                assert_eq!(fold.ticks(), k);
                assert!(!fold.ready(n), "not ready after {k} of {n}");
            }
            fold.push(&one_container_batch(interval_s * 1000));
            assert!(fold.ready(n));
            let h = fold.finish(&one_container_batch(interval_s * 1000));
            assert_eq!(
                h.interval_ms, 60_000,
                "summed sample intervals at {interval_s}s"
            );
            assert_eq!(h.resolution_secs, 60);
            assert_eq!(h.containers[0].samples, n);
            assert_eq!(h.containers[0].cpu.usage_usec, 1_000 * u64::from(n));
        }
    }

    #[test]
    fn batches_are_chunked_with_the_node_envelope_repeated() {
        let mut b = one_container_batch(5000);
        let template = b.containers[0].clone();
        b.containers = (0..601)
            .map(|i| ContainerSample {
                container_uid: format!("u/c{i}"),
                ..template.clone()
            })
            .collect();
        let chunks = chunk_batch(b.clone(), 250);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].containers.len(), 250);
        assert_eq!(chunks[2].containers.len(), 101);
        assert!(chunks
            .iter()
            .all(|c| c.node == "n" && c.interval_ms == 5000));
        assert_eq!(chunks[2].containers[100].container_uid, "u/c600");
        // Small and empty batches are one POST.
        assert_eq!(chunk_batch(one_container_batch(1), 250).len(), 1);
        assert_eq!(chunk_batch(empty_batch(1), 250).len(), 1);
        let h = MinuteFold::default().finish(&b);
        assert_eq!(chunk_history(h, 250).len(), 1);
    }

    #[test]
    fn transient_culprits_rebuild_the_index_at_most_once_per_six_ticks() {
        let base =
            std::env::temp_dir().join(format!("kg-compute-ratelimit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("cgroup");
        let proc_ = base.join("proc");
        std::fs::create_dir_all(proc_.join("pressure")).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("cgroup.controllers"), "cpu memory\n").unwrap();
        std::fs::write(
            proc_.join("pressure/cpu"),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )
        .unwrap();
        std::fs::write(proc_.join("stat"), PROC_STAT).unwrap();
        std::fs::write(proc_.join("meminfo"), MEMINFO).unwrap();
        let rel = "kubepods.slice/x.scope";
        write_cgroup(&root.join(rel), 1_000, 100);
        let registry: ComputeMap = Arc::new(ComputeRegistry::new());
        let events = registry.subscribe();
        registry.insert_container(ContainerCompute {
            pod_uid: "u1".into(),
            namespace: "n".into(),
            pod_name: "p".into(),
            container_name: "c".into(),
            container_id: "a".into(),
            pid: 1,
            cgroup_path: rel.into(),
            cgroup_id: 100,
            resources: ResourceSpec::default(),
            node: "n".into(),
        });
        let probe = FakeProbe {
            tracked: Default::default(),
            victims: vec![],
            occupancy: (0, 0, 0),
            fail: false,
            rotate_culprit: Some(9_000_000),
        };
        let cfg = ComputeConfig {
            cgroup_root: root.clone(),
            host_proc: proc_,
            ..Default::default()
        };
        let mut s = Sampler::new(cfg, "n".into(), registry, Some(Box::new(probe)), events);
        let mut usage = 1_000;
        let mut refs = Vec::new();
        for _ in 1..=8 {
            usage += 1_000;
            write_cgroup(&root.join(rel), usage, 100);
            let (b, _) = s.collect();
            refs.push(
                b.containers
                    .first()
                    .and_then(|c| c.blame.first())
                    .map(|e| e.reference.clone()),
            );
        }
        // Tick 1: periodic (first) rebuild. Ticks 2–6: rate-limited.
        // Tick 7: one on-demand rebuild. Tick 8: rate-limited again.
        assert_eq!(s.ondemand_rebuilds, 1, "{refs:?}");
        assert_eq!(s.last_rebuild_tick, 7);
        // A culprit judged after a rebuild is `exited`; one seen while
        // rate-limited is `cgroup:<id>` (not yet judged).
        assert_eq!(refs[6].as_deref(), Some("exited"));
        assert!(
            refs[7].as_deref().unwrap().starts_with("cgroup:"),
            "{refs:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_failed_snapshot_ships_null_runq_and_contention_loaded_false() {
        let base = std::env::temp_dir().join(format!("kg-compute-snapfail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("cgroup");
        let proc_ = base.join("proc");
        std::fs::create_dir_all(proc_.join("pressure")).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("cgroup.controllers"), "cpu memory\n").unwrap();
        std::fs::write(
            proc_.join("pressure/cpu"),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )
        .unwrap();
        std::fs::write(proc_.join("stat"), PROC_STAT).unwrap();
        std::fs::write(proc_.join("meminfo"), MEMINFO).unwrap();
        let rel = "kubepods.slice/x.scope";
        write_cgroup(&root.join(rel), 1_000, 100);
        let registry: ComputeMap = Arc::new(ComputeRegistry::new());
        let events = registry.subscribe();
        registry.insert_container(ContainerCompute {
            pod_uid: "u1".into(),
            namespace: "n".into(),
            pod_name: "p".into(),
            container_name: "c".into(),
            container_id: "a".into(),
            pid: 1,
            cgroup_path: rel.into(),
            cgroup_id: 100,
            resources: ResourceSpec::default(),
            node: "n".into(),
        });
        let probe = FakeProbe {
            tracked: Default::default(),
            victims: vec![],
            occupancy: (0, 0, 0),
            fail: true,
            rotate_culprit: None,
        };
        let cfg = ComputeConfig {
            cgroup_root: root.clone(),
            host_proc: proc_,
            ..Default::default()
        };
        let mut s = Sampler::new(cfg, "n".into(), registry, Some(Box::new(probe)), events);
        assert!(s.contention_loaded(), "the probe is loaded…");
        let _ = s.collect();
        write_cgroup(&root.join(rel), 2_000, 100);
        let (b, _) = s.collect();
        assert!(!b.contention_loaded, "…but this tick could not read it");
        assert_eq!(b.containers.len(), 1);
        assert!(b.containers[0].runq.is_none(), "null, not a row of zeros");
        assert_eq!(b.bpf_occupancy, BpfOccupancy::default());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_disabled_controller_posts_a_node_only_heartbeat() {
        let base = std::env::temp_dir().join(format!("kg-compute-hb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("proc/pressure")).unwrap();
        std::fs::write(base.join("proc/stat"), PROC_STAT).unwrap();
        std::fs::write(base.join("proc/meminfo"), MEMINFO).unwrap();
        std::fs::write(
            base.join("proc/pressure/cpu"),
            "some avg10=1.50 avg60=0.00 avg300=0.00 total=0\n",
        )
        .unwrap();
        let cfg = ComputeConfig {
            enabled: false,
            host_proc: base.join("proc"),
            cgroup_root: base.join("no-cgroup-mount"),
            ..Default::default()
        };
        let b = disabled_heartbeat(&cfg, "worker-9");
        assert!(!b.compute_enabled);
        assert!(!b.contention_loaded);
        assert!(!b.compute_supported, "no cgroup root mounted");
        assert!(b.containers.is_empty());
        assert_eq!(b.interval_ms, 300_000);
        assert_eq!(b.node, "worker-9");
        assert_eq!(b.node_capacity.cpu_cores, 4);
        assert!((b.node_pressure.cpu_some10 - 1.5).abs() < 1e-9);
        assert_eq!(b.bpf_occupancy, BpfOccupancy::default());
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["compute_enabled"], false);
        assert_eq!(v["containers"].as_array().unwrap().len(), 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn sample_batch_serialises_to_the_contract_shape() {
        let cont = ContainerCompute {
            pod_uid: "u".into(),
            namespace: "payments".into(),
            pod_name: "api".into(),
            container_name: "api".into(),
            container_id: "x".into(),
            pid: 1,
            cgroup_path: "x".into(),
            cgroup_id: 18944,
            resources: ResourceSpec::default(),
            node: "n".into(),
        };
        let s = container_sample(
            &cont,
            &CgroupRaw::default(),
            &Counters::default(),
            None,
            vec![BlameEntry {
                cgroup_id: 77,
                kind: "system",
                reference: "system.slice/kubelet.service".into(),
                container_uid: None,
                count: 1,
                wait_ns: 2,
            }],
        );
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["container_uid"], "u/api");
        assert_eq!(v["cpu"]["quota_usec"], serde_json::Value::Null);
        assert_eq!(v["cpu"]["period_usec"], 100_000);
        assert_eq!(v["memory"]["limit"], serde_json::Value::Null);
        assert_eq!(v["runq"], serde_json::Value::Null);
        assert_eq!(v["blame"][0]["ref"], "system.slice/kubelet.service");
        assert_eq!(v["blame"][0]["container_uid"], serde_json::Value::Null);
        assert_eq!(v["blame"][0]["kind"], "system");
    }

    // ---- an end-to-end tick against a fixture cgroup tree and a fake probe ----

    /// A probe that answers from plain data, rebuilt on every snapshot,
    /// so the test depends on nothing but the contract's field names.
    /// (culprit cgroup id, count, wait_ns)
    type FakePair = (u64, u64, u64);
    /// (victim cgroup id, hist delta, pairs)
    type FakeVictim = (u64, [u64; 24], Vec<FakePair>);

    struct FakeProbe {
        tracked: std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
        victims: Vec<FakeVictim>,
        occupancy: (u64, u64, u64),
        /// Make `snapshot()` fail.
        fail: bool,
        /// When set, every snapshot names a fresh, never-seen culprit id
        /// (a transient scope) for victim 100.
        rotate_culprit: Option<u64>,
    }

    impl ContentionSource for FakeProbe {
        fn track(&self, id: u64) -> anyhow::Result<()> {
            self.tracked.lock().unwrap().push(id);
            Ok(())
        }
        fn untrack(&self, id: u64) -> anyhow::Result<()> {
            self.tracked.lock().unwrap().retain(|x| *x != id);
            Ok(())
        }
        fn snapshot(&mut self) -> anyhow::Result<ContentionSnapshot> {
            if self.fail {
                anyhow::bail!("map read failed");
            }
            if let Some(next) = self.rotate_culprit.as_mut() {
                *next += 1;
                self.victims = vec![(100, [0; 24], vec![(*next, 1, 1)])];
            }
            let mut per_victim = HashMap::new();
            for (victim, hist, pairs) in &self.victims {
                per_victim.insert(
                    *victim,
                    VictimStats {
                        hist_delta: *hist,
                        pairs: pairs
                            .iter()
                            .map(|(c, n, w)| PairDelta {
                                culprit_cgroup_id: *c,
                                count: *n,
                                wait_ns: *w,
                            })
                            .collect(),
                    },
                );
            }
            Ok(ContentionSnapshot {
                per_victim,
                map_occupancy: MapOccupancy {
                    runq_enqueued: self.occupancy.0,
                    runq_hist: self.occupancy.1,
                    pair: self.occupancy.2,
                    ..Default::default()
                },
            })
        }
    }

    fn write_cgroup(dir: &Path, usage: u64, current: u64) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("cpu.stat"),
            format!("usage_usec {usage}\nuser_usec 0\nsystem_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n"),
        )
        .unwrap();
        std::fs::write(dir.join("cpu.max"), "max 100000\n").unwrap();
        std::fs::write(dir.join("cpu.pressure"), CPU_PRESSURE).unwrap();
        std::fs::write(dir.join("memory.current"), format!("{current}\n")).unwrap();
        std::fs::write(dir.join("memory.max"), "max\n").unwrap();
        std::fs::write(dir.join("memory.stat"), MEMORY_STAT).unwrap();
        std::fs::write(dir.join("memory.events"), MEMORY_EVENTS).unwrap();
    }

    #[test]
    fn probe_failure_counters_ship_as_interval_deltas() {
        let occ = |h, p| MapOccupancy {
            runq_enqueued: 0,
            runq_hist: 0,
            pair: 0,
            hist_update_failures: h,
            pair_update_failures: p,
        };
        // First snapshot: everything since load is this interval's delta.
        let (h, p, prev) = failure_deltas((0, 0), &occ(7, 3));
        assert_eq!((h, p), (7, 3));
        // Quiet interval: zero, so a one-off burst does not stick.
        let (h, p, prev) = failure_deltas(prev, &occ(7, 3));
        assert_eq!((h, p), (0, 0));
        // New failures: only the increase.
        let (h, p, prev) = failure_deltas(prev, &occ(9, 3));
        assert_eq!((h, p), (2, 0));
        // Probe reloaded (counters reset): re-baseline, never underflow.
        let (h, p, _) = failure_deltas(prev, &occ(1, 0));
        assert_eq!((h, p), (0, 0));
    }

    #[test]
    fn a_tick_against_a_fixture_tree_produces_deltas_runq_and_blame() {
        let base = std::env::temp_dir().join(format!("kg-compute-tick-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("cgroup");
        let proc_ = base.join("proc");
        std::fs::create_dir_all(proc_.join("pressure")).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("cgroup.controllers"), "cpu memory\n").unwrap();
        std::fs::write(
            proc_.join("pressure/cpu"),
            "some avg10=3.10 avg60=0.00 avg300=0.00 total=1\n",
        )
        .unwrap();
        std::fs::write(proc_.join("pressure/memory"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
        std::fs::write(proc_.join("stat"), PROC_STAT).unwrap();
        std::fs::write(proc_.join("meminfo"), MEMINFO).unwrap();

        let pod_rel = "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podu1.slice";
        let api_rel = format!("{pod_rel}/cri-containerd-a.scope");
        write_cgroup(&root.join(&api_rel), 1_000, 100);

        let registry: ComputeMap = Arc::new(ComputeRegistry::new());
        let events = registry.subscribe();
        registry.insert_container(ContainerCompute {
            pod_uid: "u1".into(),
            namespace: "payments".into(),
            pod_name: "api-1".into(),
            container_name: "api".into(),
            container_id: "a".into(),
            pid: 1,
            cgroup_path: api_rel.clone(),
            cgroup_id: 100,
            resources: ResourceSpec {
                cpu_request_millis: Some(250),
                ..Default::default()
            },
            node: "n".into(),
        });
        // The bully: opted out with `kguardian.dev/compute: "off"`, so
        // identity-only — never sampled, never tracked, still named.
        registry.insert_identity_only(ContainerCompute {
            pod_uid: "u2".into(),
            namespace: "batch".into(),
            pod_name: "etl-1".into(),
            container_name: "worker".into(),
            container_id: "b".into(),
            pid: 2,
            cgroup_path: "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podu2.slice/cri-containerd-b.scope".into(),
            cgroup_id: 200,
            resources: ResourceSpec::default(),
            node: "n".into(),
        });

        let mut hist = [0u64; 24];
        hist[6] = 300; // 64–128 µs
        hist[14] = 40; // 16–32 ms
        let tracked = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let probe = FakeProbe {
            tracked: std::sync::Arc::clone(&tracked),
            victims: vec![(
                100,
                hist,
                vec![(200, 210, 6_100_000_000), (0, 3, 1_000), (424242, 1, 2_000)],
            )],
            occupancy: (11, 22, 33),
            fail: false,
            rotate_culprit: None,
        };
        let cfg = ComputeConfig {
            cgroup_root: root.clone(),
            host_proc: proc_.clone(),
            ..Default::default()
        };
        let mut s = Sampler::new(
            cfg,
            "worker-3".into(),
            Arc::clone(&registry),
            Some(Box::new(probe)),
            events,
        );
        assert!(s.supported());

        // First tick seeds counters: envelope only.
        let (b1, h1) = s.collect();
        assert!(h1.is_none());
        assert!(b1.containers.is_empty());
        assert_eq!(b1.node, "worker-3");
        assert!(b1.compute_supported && b1.contention_loaded && b1.compute_enabled);
        assert_eq!(b1.node_capacity.cpu_cores, 4);
        assert_eq!(b1.node_capacity.memory_bytes, 32_768_000 * 1024);
        assert!((b1.node_pressure.cpu_some10 - 3.1).abs() < 1e-9);
        assert_eq!(b1.bpf_occupancy.pair, 33);

        // Advance the fixture and tick again.
        write_cgroup(&root.join(&api_rel), 2_500, 150);
        let (b2, _) = s.collect();
        assert_eq!(b2.containers.len(), 1, "the opted-out bully is not sampled");
        let c = &b2.containers[0];
        assert_eq!(c.container_uid, "u1/api");
        assert_eq!(c.cpu.usage_usec, 1_500);
        assert_eq!(c.cpu.request_millis, Some(250));
        assert_eq!(c.cpu.quota_usec, None);
        assert_eq!(c.memory.current, 150);
        assert_eq!(
            c.memory.working_set, 0,
            "inactive_file exceeds current in the fixture"
        );
        assert_eq!(c.memory.limit, None);
        assert!((c.cpu.psi_some10 - 12.4).abs() < 1e-9);
        let r = c.runq.as_ref().unwrap();
        assert_eq!(r.count, 340);
        assert_eq!(r.hist[14], 40);
        assert!(
            r.p99_us >= 16_384,
            "p99 must land in the 16–32 ms bucket, got {}",
            r.p99_us
        );
        assert_eq!(c.blame.len(), 3);
        // The opted-out bully is named with its full identity, resolved
        // from the identity-only tier before the cgroup index.
        assert_eq!(c.blame[0].cgroup_id, 200);
        assert_eq!(c.blame[0].kind, "pod");
        assert_eq!(c.blame[0].reference, "batch/etl-1/worker");
        assert_eq!(c.blame[0].container_uid.as_deref(), Some("u2/worker"));
        let kernel = c.blame.iter().find(|b| b.cgroup_id == 0).unwrap();
        assert_eq!(
            (kernel.kind, kernel.reference.as_str()),
            ("kernel", "kernel")
        );
        let unknown = c.blame.iter().find(|b| b.cgroup_id == 424242).unwrap();
        assert_eq!(
            (unknown.kind, unknown.reference.as_str()),
            ("unknown", "exited"),
            "judged after the tick-1 rebuild and still absent"
        );
        // 2 000 ns unknown out of 6 100 001 000 ns of blamed wait.
        assert!(b2.unknown_blame_share < 1e-5 && b2.unknown_blame_share > 0.0);

        // The probe was told to track the sampled container only —
        // never the opted-out one.
        assert!(s.tracked_synced);
        assert_eq!(*tracked.lock().unwrap(), vec![100u64]);

        // Removing the pod forgets its counters and untracks it.
        registry.remove_pod("u1");
        let (b3, _) = s.collect();
        assert!(b3.containers.is_empty());
        assert!(s.prev.is_empty());
        assert!(tracked.lock().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn unsupported_node_reports_itself_without_sampling() {
        let base = std::env::temp_dir().join(format!("kg-compute-unsup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("proc")).unwrap();
        std::fs::create_dir_all(base.join("cgroup")).unwrap();
        // cgroup v1: no cgroup.controllers file.
        let cfg = ComputeConfig {
            cgroup_root: base.join("cgroup"),
            host_proc: base.join("proc"),
            ..Default::default()
        };
        let registry: ComputeMap = Arc::new(ComputeRegistry::new());
        let events = registry.subscribe();
        let mut s = Sampler::new(cfg, "n".into(), registry, None, events);
        assert!(!s.supported());
        let (b, _) = s.collect();
        assert!(!b.compute_supported);
        assert!(!b.contention_loaded);
        assert!(b.containers.is_empty());
        assert_eq!(b.node_capacity.cpu_cores, 0);
        let _ = std::fs::remove_dir_all(&base);
    }
}
