//! Userspace side of the scheduler-contention probe
//! (`src/bpf/sched_contention.bpf.c`).
//!
//! The kernel keeps two cumulative maps — a per-victim run-queue latency
//! histogram and a victim<-culprit preemption-pair matrix — and this
//! module reads them once per sample interval, diffs against its previous
//! read, and hands the deltas to the compute sampler. Nothing is ever
//! zeroed on the kernel side; the cumulative counters stay put and the
//! subtraction happens here, so a slow or skipped sample never loses
//! events.
//!
//! Design: `docs/design/compute-contention-monitoring.md`, D4 / Phase 2.
//! Wire contract: `ContentionProbe`, `ContentionSnapshot`,
//! `quantiles_from_hist` — the names and shapes are pinned by the
//! compute-contention contract; keep them stable.

use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::path::Path;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, OpenObject};
use tracing::{info, warn};

use crate::Error;

pub mod sched_contention_skel {
    include!(concat!(env!("OUT_DIR"), "/sched_contention.skel.rs"));
}

use sched_contention_skel::{
    OpenSchedContentionSkel, SchedContentionSkel, SchedContentionSkelBuilder,
};

/// Number of histogram buckets. Bucket `b` covers `[2^b, 2^(b+1))` µs;
/// bucket 23 is the overflow bucket (`>= 2^23` µs ≈ 8.4 s).
pub const RUNQ_HIST_BUCKETS: usize = 24;
const OVERFLOW_BUCKET: usize = RUNQ_HIST_BUCKETS - 1;

/// Deltas since the previous `snapshot()`, per victim cgroup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentionSnapshot {
    pub per_victim: HashMap<u64, VictimStats>,
    pub map_occupancy: MapOccupancy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VictimStats {
    /// Per-bucket increments since the previous snapshot.
    pub hist_delta: [u64; RUNQ_HIST_BUCKETS],
    /// Pair increments since the previous snapshot; only pairs with a
    /// non-zero delta are listed.
    pub pairs: Vec<PairDelta>,
}

impl Default for VictimStats {
    fn default() -> Self {
        Self {
            hist_delta: [0; RUNQ_HIST_BUCKETS],
            pairs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairDelta {
    pub culprit_cgroup_id: u64,
    pub count: u64,
    pub wait_ns: u64,
}

/// Live key counts of the kernel maps. Exported per node so a leak is a
/// number on a dashboard rather than a phantom p99.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MapOccupancy {
    pub runq_enqueued: u64,
    pub runq_hist: u64,
    pub pair: u64,
}

/// Quantiles derived from a 24-bucket log2 histogram. See
/// [`quantiles_from_hist`] for the exact semantics of each field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunqQuantiles {
    /// Total samples, overflow included.
    pub count: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    /// Upper bound of the highest NON-overflow bucket with a count.
    pub max_us: u64,
    /// Samples `>= 2^23` µs. Never folded into `max_us` or a quantile.
    pub overflow: u64,
}

/// Which tracepoint program family is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachFamily {
    /// `tp_btf/*`: typed arguments, fastest; needs vmlinux BTF.
    TpBtf,
    /// `raw_tp/*`: untyped raw tracepoints; the fallback.
    RawTp,
}

type HistKey = (u64, u32);
type PairKey = (u64, u64);
type PairCounters = (u64, u64);

pub struct ContentionProbe {
    skel: SchedContentionSkel<'static>,
    family: AttachFamily,
    prev_hist: HashMap<HistKey, u64>,
    prev_pair: HashMap<PairKey, PairCounters>,
}

impl std::fmt::Debug for ContentionProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentionProbe")
            .field("family", &self.family)
            .field("prev_hist_keys", &self.prev_hist.len())
            .field("prev_pair_keys", &self.prev_pair.len())
            .finish()
    }
}

impl ContentionProbe {
    /// Open, load and attach the probe. Tries the `tp_btf` family first
    /// (when `/sys/kernel/btf/vmlinux` exists), then `raw_tp`. `Err`
    /// means neither family attached; the caller records
    /// `contention_loaded=false` and carries on without blame data.
    ///
    /// `min_runq_latency_us` is written to `probe_config[0]` (in ns) between
    /// load and attach, so no event is ever evaluated against a zero.
    pub fn load(min_runq_latency_us: u64) -> Result<Self, Error> {
        let min_ns = min_runq_latency_us.saturating_mul(1_000);
        let mut attempts: Vec<(AttachFamily, libbpf_rs::Error)> = Vec::new();

        if Path::new("/sys/kernel/btf/vmlinux").exists() {
            match open_load_attach(AttachFamily::TpBtf, min_ns) {
                Ok(skel) => return Ok(Self::new(skel, AttachFamily::TpBtf)),
                Err(e) => {
                    warn!("sched_contention tp_btf programs failed to load ({e}); trying raw_tp");
                    attempts.push((AttachFamily::TpBtf, e));
                }
            }
        } else {
            warn!("/sys/kernel/btf/vmlinux missing; sched_contention will use raw_tp programs");
        }

        match open_load_attach(AttachFamily::RawTp, min_ns) {
            Ok(skel) => Ok(Self::new(skel, AttachFamily::RawTp)),
            Err(e) => {
                attempts.push((AttachFamily::RawTp, e));
                let detail = attempts
                    .iter()
                    .map(|(f, e)| format!("{f:?}: {e}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(Error::Custom(format!(
                    "sched_contention probe could not be attached ({detail})"
                )))
            }
        }
    }

    fn new(skel: SchedContentionSkel<'static>, family: AttachFamily) -> Self {
        info!("sched_contention probe attached via {family:?}");
        Self {
            skel,
            family,
            prev_hist: HashMap::new(),
            prev_pair: HashMap::new(),
        }
    }

    pub fn family(&self) -> AttachFamily {
        self.family
    }

    /// Start recording `cgroup_id` as a victim.
    pub fn track(&self, cgroup_id: u64) -> Result<(), Error> {
        self.skel
            .maps
            .tracked_cgroups
            .update(&cgroup_id.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
            .map_err(|e| Error::Custom(format!("tracked_cgroups insert {cgroup_id}: {e}")))
    }

    /// Stop recording `cgroup_id` and release its histogram rows.
    ///
    /// `runq_hist` is a plain HASH that nothing in the kernel ever frees,
    /// so without this each dead pod would leave 24 rows behind and the
    /// map (8192 rows ≈ 341 cgroups) would fill under ordinary pod churn,
    /// after which NEW pods silently get no histogram. The pair map is
    /// LRU and ages out on its own; its rows for this victim are left to
    /// it. The userspace baseline needs no cleanup: `snapshot()` replaces
    /// it wholesale with each read, so a vanished key is forgotten on the
    /// next call and a recycled cgroup id that reappears from zero is
    /// re-baselined by `counter_delta`. A missing key is not an error.
    pub fn untrack(&self, cgroup_id: u64) -> Result<(), Error> {
        let maps = &self.skel.maps;
        match maps.tracked_cgroups.delete(&cgroup_id.to_ne_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::Custom(format!(
                    "tracked_cgroups delete {cgroup_id}: {e}"
                )))
            }
        }
        for bucket in 0..RUNQ_HIST_BUCKETS as u32 {
            let key = hist_key_to_bytes(cgroup_id, bucket);
            match maps.runq_hist.delete(&key) {
                Ok(()) => {}
                Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Error::Custom(format!(
                        "runq_hist delete {cgroup_id}/{bucket}: {e}"
                    )))
                }
            }
        }
        Ok(())
    }

    /// Read both aggregate maps and return the increments since the
    /// previous call. The kernel maps are left untouched (cumulative);
    /// the previous read is replaced by this one.
    ///
    /// The first call after `load` reports everything recorded so far as
    /// a delta, which is correct: nothing was reported before.
    pub fn snapshot(&mut self) -> Result<ContentionSnapshot, Error> {
        let maps = &self.skel.maps;

        let mut cur_hist: HashMap<HistKey, u64> = HashMap::new();
        for key in maps.runq_hist.keys() {
            let Some((cgroup_id, bucket)) = hist_key_from_bytes(&key) else {
                continue;
            };
            let Some(value) = maps
                .runq_hist
                .lookup(&key, MapFlags::ANY)
                .map_err(|e| Error::Custom(format!("runq_hist lookup: {e}")))?
            else {
                continue; // deleted between keys() and lookup()
            };
            let Some(count) = u64_from_bytes(&value) else {
                continue;
            };
            cur_hist.insert((cgroup_id, bucket), count);
        }

        let mut cur_pair: HashMap<PairKey, PairCounters> = HashMap::new();
        for key in maps.pair.keys() {
            let Some(pk) = pair_key_from_bytes(&key) else {
                continue;
            };
            let Some(value) = maps
                .pair
                .lookup(&key, MapFlags::ANY)
                .map_err(|e| Error::Custom(format!("pair lookup: {e}")))?
            else {
                continue;
            };
            let Some(pv) = pair_value_from_bytes(&value) else {
                continue;
            };
            cur_pair.insert(pk, pv);
        }

        let runq_enqueued = maps.runq_enqueued.keys().count() as u64;
        let occupancy = MapOccupancy {
            runq_enqueued,
            runq_hist: cur_hist.len() as u64,
            pair: cur_pair.len() as u64,
        };

        let mut snapshot = compute_deltas(&self.prev_hist, &cur_hist, &self.prev_pair, &cur_pair);
        snapshot.map_occupancy = occupancy;

        self.prev_hist = cur_hist;
        self.prev_pair = cur_pair;
        Ok(snapshot)
    }
}

/// Open the skeleton with exactly one program family autoloaded, load,
/// write `config[0]`, attach.
///
/// The skeleton borrows its `OpenObject` storage for its whole life, so
/// storing it in a struct needs a `'static` borrow; the storage (one
/// pointer-sized `MaybeUninit`) is `Box::leak`ed. The probe is a
/// once-per-process singleton, and a failed attempt leaks the same 8
/// bytes, once — the object itself is still dropped and closed.
fn open_load_attach(
    family: AttachFamily,
    min_ns: u64,
) -> Result<SchedContentionSkel<'static>, libbpf_rs::Error> {
    let storage: &'static mut MaybeUninit<OpenObject> = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut open = SchedContentionSkelBuilder::default().open(storage)?;
    select_family(&mut open, family);

    let mut skel = open.load()?;
    skel.maps
        .probe_config
        .update(&0u32.to_ne_bytes(), &min_ns.to_ne_bytes(), MapFlags::ANY)?;
    skel.attach()?;
    Ok(skel)
}

fn select_family(open: &mut OpenSchedContentionSkel<'_>, family: AttachFamily) {
    let progs = &mut open.progs;
    let tp_btf = family == AttachFamily::TpBtf;
    progs.tp_btf_sched_wakeup.set_autoload(tp_btf);
    progs.tp_btf_sched_wakeup_new.set_autoload(tp_btf);
    progs.tp_btf_sched_switch.set_autoload(tp_btf);
    progs.tp_btf_sched_process_exit.set_autoload(tp_btf);
    progs.raw_tp_sched_wakeup.set_autoload(!tp_btf);
    progs.raw_tp_sched_wakeup_new.set_autoload(!tp_btf);
    progs.raw_tp_sched_switch.set_autoload(!tp_btf);
    progs.raw_tp_sched_process_exit.set_autoload(!tp_btf);
}

/// Delta of one cumulative counter.
///
/// `cur < prev` cannot happen for a key that stayed in a cumulative map;
/// it means the key was evicted (the `pair` map is LRU) and re-created
/// from zero since the last read. Everything the new entry holds is
/// then genuinely new, so the entry is treated as a fresh baseline and
/// `cur` itself is the delta — never a wrapped negative number.
fn counter_delta(prev: u64, cur: u64) -> u64 {
    if cur >= prev {
        cur - prev
    } else {
        cur
    }
}

/// Pure diff of two map reads. A key present only in `cur` is a fresh
/// baseline (delta = value); a key present only in `prev` was evicted or
/// untracked and contributes nothing. Every victim that has ANY row in
/// `cur_hist` appears in the result even with an all-zero delta, so a
/// tracked pod that waited for nothing this interval still reports a
/// zero histogram rather than vanishing.
fn compute_deltas(
    prev_hist: &HashMap<HistKey, u64>,
    cur_hist: &HashMap<HistKey, u64>,
    prev_pair: &HashMap<PairKey, PairCounters>,
    cur_pair: &HashMap<PairKey, PairCounters>,
) -> ContentionSnapshot {
    let mut per_victim: HashMap<u64, VictimStats> = HashMap::new();

    for (&(cgroup_id, bucket), &cur) in cur_hist {
        let bucket = bucket as usize;
        if bucket >= RUNQ_HIST_BUCKETS {
            continue;
        }
        let prev = prev_hist
            .get(&(cgroup_id, bucket as u32))
            .copied()
            .unwrap_or(0);
        per_victim.entry(cgroup_id).or_default().hist_delta[bucket] = counter_delta(prev, cur);
    }

    for (&(victim, culprit), &(cur_count, cur_wait)) in cur_pair {
        let (prev_count, prev_wait) = prev_pair.get(&(victim, culprit)).copied().unwrap_or((0, 0));
        // One eviction re-baselines both counters together: if the count
        // went backwards the wait did too (same row), so both take `cur`.
        let (count, wait_ns) = if cur_count < prev_count {
            (cur_count, cur_wait)
        } else {
            (cur_count - prev_count, counter_delta(prev_wait, cur_wait))
        };
        if count == 0 && wait_ns == 0 {
            continue;
        }
        per_victim.entry(victim).or_default().pairs.push(PairDelta {
            culprit_cgroup_id: culprit,
            count,
            wait_ns,
        });
    }

    for stats in per_victim.values_mut() {
        stats.pairs.sort_by(|a, b| {
            b.wait_ns
                .cmp(&a.wait_ns)
                .then(a.culprit_cgroup_id.cmp(&b.culprit_cgroup_id))
        });
    }

    ContentionSnapshot {
        per_victim,
        map_occupancy: MapOccupancy::default(),
    }
}

/// Upper bound (µs) of histogram bucket `b`: bucket `b` covers
/// `[2^b, 2^(b+1))`.
fn bucket_upper_us(b: usize) -> u64 {
    1u64 << (b + 1)
}

/// Quantiles from a 24-bucket log2 histogram.
///
/// - `count` is the total over all 24 buckets, overflow included.
/// - A quantile `q` is the upper bound of the first bucket at which the
///   cumulative count reaches `ceil(q * count)`.
/// - `max_us` is the upper bound of the highest non-overflow bucket with
///   a count; 0 when no finite bucket has one.
/// - `overflow` is `hist[23]` verbatim.
///
/// Censoring rule: when a quantile's target falls inside the overflow
/// bucket (e.g. p99 with > 1 % of samples ≥ 2^23 µs) the function
/// reports `max_us` — the highest FINITE bound — and leaves `overflow`
/// non-zero. It never invents a finite number out of bucket 23 (the
/// reference implementation clamped overflow to a finite `le` and
/// published an 8 s p99 that did not exist). Consumers must therefore
/// read `overflow` alongside any quantile: `overflow > 0` means the
/// upper quantiles are lower bounds, not estimates.
pub fn quantiles_from_hist(hist: &[u64; RUNQ_HIST_BUCKETS]) -> RunqQuantiles {
    let overflow = hist[OVERFLOW_BUCKET];
    let count = hist.iter().fold(0u64, |acc, &c| acc.saturating_add(c));

    let max_us = hist[..OVERFLOW_BUCKET]
        .iter()
        .rposition(|&c| c > 0)
        .map(bucket_upper_us)
        .unwrap_or(0);

    if count == 0 {
        return RunqQuantiles::default();
    }

    let quantile = |num: u64, den: u64| -> u64 {
        // ceil(count * num / den) without overflow for realistic counts.
        let target = (count as u128 * num as u128).div_ceil(den as u128) as u64;
        let mut cumulative = 0u64;
        for (b, &c) in hist[..OVERFLOW_BUCKET].iter().enumerate() {
            cumulative = cumulative.saturating_add(c);
            if cumulative >= target {
                return bucket_upper_us(b);
            }
        }
        // Target lies in the overflow bucket: censored, report the
        // highest finite bound.
        max_us
    };

    RunqQuantiles {
        count,
        p50_us: quantile(50, 100),
        p95_us: quantile(95, 100),
        p99_us: quantile(99, 100),
        max_us,
        overflow,
    }
}

// ---- raw map key/value codecs ---------------------------------------
//
// Layouts are `struct runq_hist_key`, `struct pair_key`,
// `struct pair_value` in src/bpf/sched_contention.h: all 16 bytes,
// native endian, no padding beyond the explicit `pad`.

fn u64_from_bytes(b: &[u8]) -> Option<u64> {
    b.get(..8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_ne_bytes)
}

fn u32_from_bytes(b: &[u8]) -> Option<u32> {
    b.get(..4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_ne_bytes)
}

fn hist_key_to_bytes(cgroup_id: u64, bucket: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&cgroup_id.to_ne_bytes());
    out[8..12].copy_from_slice(&bucket.to_ne_bytes());
    out
}

fn hist_key_from_bytes(b: &[u8]) -> Option<HistKey> {
    if b.len() < 16 {
        return None;
    }
    Some((u64_from_bytes(&b[..8])?, u32_from_bytes(&b[8..12])?))
}

fn pair_key_from_bytes(b: &[u8]) -> Option<PairKey> {
    if b.len() < 16 {
        return None;
    }
    Some((u64_from_bytes(&b[..8])?, u64_from_bytes(&b[8..16])?))
}

fn pair_value_from_bytes(b: &[u8]) -> Option<PairCounters> {
    if b.len() < 16 {
        return None;
    }
    Some((u64_from_bytes(&b[..8])?, u64_from_bytes(&b[8..16])?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hist_with(entries: &[(usize, u64)]) -> [u64; RUNQ_HIST_BUCKETS] {
        let mut h = [0u64; RUNQ_HIST_BUCKETS];
        for &(b, c) in entries {
            h[b] = c;
        }
        h
    }

    #[test]
    fn quantiles_empty_hist_is_all_zero() {
        let q = quantiles_from_hist(&[0; RUNQ_HIST_BUCKETS]);
        assert_eq!(q, RunqQuantiles::default());
    }

    #[test]
    fn quantiles_single_bucket_reports_its_upper_bound() {
        // Bucket 5 = [32, 64) µs.
        let q = quantiles_from_hist(&hist_with(&[(5, 10)]));
        assert_eq!(q.count, 10);
        assert_eq!(q.p50_us, 64);
        assert_eq!(q.p95_us, 64);
        assert_eq!(q.p99_us, 64);
        assert_eq!(q.max_us, 64);
        assert_eq!(q.overflow, 0);
    }

    #[test]
    fn quantiles_overflow_only_never_yields_a_finite_number() {
        let q = quantiles_from_hist(&hist_with(&[(OVERFLOW_BUCKET, 7)]));
        assert_eq!(q.count, 7);
        assert_eq!(q.overflow, 7);
        // No finite bucket has a count: max is 0 and every quantile is
        // censored to it. Nothing derived from 2^23 or 2^24 appears.
        assert_eq!(q.max_us, 0);
        assert_eq!(q.p50_us, 0);
        assert_eq!(q.p95_us, 0);
        assert_eq!(q.p99_us, 0);
    }

    #[test]
    fn quantiles_mixed_overflow_censors_upper_quantiles_to_finite_max() {
        // 90 samples in [8,16) µs, 10 in overflow.
        let q = quantiles_from_hist(&hist_with(&[(3, 90), (OVERFLOW_BUCKET, 10)]));
        assert_eq!(q.count, 100);
        assert_eq!(q.p50_us, 16);
        // p95 target = 95 > 90 finite samples: censored.
        assert_eq!(q.p95_us, 16);
        assert_eq!(q.p99_us, 16);
        assert_eq!(q.max_us, 16);
        assert_eq!(q.overflow, 10);
        assert_ne!(q.p99_us, bucket_upper_us(OVERFLOW_BUCKET));
    }

    #[test]
    fn quantiles_spread_across_buckets() {
        // 50 @ [1,2), 45 @ [256,512), 4 @ [16384,32768), 1 @ [2^22, 2^23)
        let q = quantiles_from_hist(&hist_with(&[(0, 50), (8, 45), (14, 4), (22, 1)]));
        assert_eq!(q.count, 100);
        assert_eq!(q.p50_us, 2); // cumulative hits 50 in bucket 0
        assert_eq!(q.p95_us, 512); // 95 in bucket 8
        assert_eq!(q.p99_us, 32_768); // 99 in bucket 14
        assert_eq!(q.max_us, 1 << 23);
        assert_eq!(q.overflow, 0);
    }

    #[test]
    fn counter_delta_rebaselines_on_eviction() {
        assert_eq!(counter_delta(10, 15), 5);
        assert_eq!(counter_delta(10, 10), 0);
        // Evicted and re-created from zero: cur is the delta, not wrap.
        assert_eq!(counter_delta(500, 3), 3);
    }

    #[test]
    fn compute_deltas_diffs_hist_and_pairs_against_previous_read() {
        let victim = 0x1000u64;
        let other = 0x2000u64;
        let culprit_a = 0xa0u64;
        let culprit_b = 0xb0u64;

        let prev_hist: HashMap<HistKey, u64> =
            [((victim, 3), 100), ((victim, 7), 5), ((other, 2), 1)].into();
        let cur_hist: HashMap<HistKey, u64> = [
            ((victim, 3), 130),
            ((victim, 7), 5),
            ((victim, 9), 2),
            ((other, 2), 1),
        ]
        .into();

        let prev_pair: HashMap<PairKey, PairCounters> = [
            ((victim, culprit_a), (40, 4_000)),
            ((victim, culprit_b), (900, 90_000)),
        ]
        .into();
        // culprit_b was LRU-evicted and came back with a small count;
        // culprit_a advanced normally; a brand-new culprit 0 (kernel)
        // appears.
        let cur_pair: HashMap<PairKey, PairCounters> = [
            ((victim, culprit_a), (52, 5_200)),
            ((victim, culprit_b), (3, 300)),
            ((victim, 0), (1, 700)),
        ]
        .into();

        let snap = compute_deltas(&prev_hist, &cur_hist, &prev_pair, &cur_pair);

        let v = snap.per_victim.get(&victim).expect("victim present");
        let mut expect = [0u64; RUNQ_HIST_BUCKETS];
        expect[3] = 30;
        expect[9] = 2;
        assert_eq!(v.hist_delta, expect);
        // Sorted by wait_ns desc.
        assert_eq!(
            v.pairs,
            vec![
                PairDelta {
                    culprit_cgroup_id: culprit_a,
                    count: 12,
                    wait_ns: 1_200
                },
                PairDelta {
                    culprit_cgroup_id: 0,
                    count: 1,
                    wait_ns: 700
                },
                PairDelta {
                    culprit_cgroup_id: culprit_b,
                    count: 3,
                    wait_ns: 300
                },
            ]
        );

        // A victim with rows but no change still appears, with zeros.
        let o = snap.per_victim.get(&other).expect("other present");
        assert_eq!(o.hist_delta, [0u64; RUNQ_HIST_BUCKETS]);
        assert!(o.pairs.is_empty());
    }

    #[test]
    fn compute_deltas_drops_keys_that_vanished() {
        let prev_hist: HashMap<HistKey, u64> = [((1, 0), 5)].into();
        let cur_hist: HashMap<HistKey, u64> = HashMap::new();
        let snap = compute_deltas(&prev_hist, &cur_hist, &HashMap::new(), &HashMap::new());
        assert!(snap.per_victim.is_empty());
    }

    #[test]
    fn key_codecs_round_trip() {
        let k = hist_key_to_bytes(0xdead_beef_0000_0001, 17);
        assert_eq!(hist_key_from_bytes(&k), Some((0xdead_beef_0000_0001, 17)));
        assert_eq!(hist_key_from_bytes(&k[..12]), None);

        let mut pk = [0u8; 16];
        pk[..8].copy_from_slice(&7u64.to_ne_bytes());
        pk[8..].copy_from_slice(&9u64.to_ne_bytes());
        assert_eq!(pair_key_from_bytes(&pk), Some((7, 9)));
        assert_eq!(pair_value_from_bytes(&pk), Some((7, 9)));
    }

    /// Loads the real probe into the running kernel. Needs CAP_BPF +
    /// CAP_PERFMON (in practice root) and a kernel with raw tracepoints;
    /// `tp_btf` additionally needs /sys/kernel/btf/vmlinux. Run on a
    /// node or a privileged dev box with:
    ///
    /// ```text
    /// cd controller
    /// cargo test --no-run contention 2>&1 | grep -o 'target/debug/deps/kguardian-[a-z0-9]*'
    /// sudo <that binary> --ignored contention::tests::probe_loads_and_snapshots -- --nocapture
    /// ```
    ///
    /// (or `sudo -E cargo test contention -- --ignored` when sudo keeps
    /// the cargo environment). The assertion is deliberately weak: it
    /// proves the verifier accepts both the program bodies and whichever
    /// family this kernel offers, and that the map codecs agree with the
    /// C layouts. It does not assert on latency values.
    #[test]
    #[ignore = "loads BPF into the running kernel; needs root / CAP_BPF"]
    fn probe_loads_and_snapshots() {
        let mut probe = ContentionProbe::load(100).expect("probe loads and attaches");
        eprintln!("attached via {:?}", probe.family());
        let cgroup_id = 0xffff_ffff_0000_0001u64;
        probe.track(cgroup_id).expect("track");
        std::thread::sleep(std::time::Duration::from_millis(200));
        let snap = probe.snapshot().expect("snapshot");
        eprintln!("occupancy {:?}", snap.map_occupancy);
        // A cgroup id that exists nowhere on the box can never be a
        // victim, so tracking it must not conjure a histogram row.
        assert!(!snap.per_victim.contains_key(&cgroup_id));
        probe.untrack(cgroup_id).expect("untrack");
        let snap2 = probe.snapshot().expect("second snapshot");
        assert!(!snap2.per_victim.contains_key(&cgroup_id));
    }
}
