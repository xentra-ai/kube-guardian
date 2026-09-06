//! Byte-exact heap profile of the broker's whole-result-set read path.
//!
//! This exists because the broker was OOMKilled (exit 137, `limits.memory:
//! 1Gi`) serving concurrent `GET /pod/traffic` reads, and the per-request
//! cost in the code comments was a guess that turned out to be 63% low (it
//! claimed ~350 JSON B/row; a real row measures 572.1). The number that sizes
//! `read_budget::TRAFFIC_ROW_COST_BYTES` comes from here, so it can be
//! re-derived rather than re-guessed.
//!
//! It lives in `tests/` — not in the lib — because it installs a
//! `#[global_allocator]`, and a global allocator is per-binary. Here it
//! affects only this test binary and never the shipped broker.
//!
//! ## What "peak" means here
//!
//! `CountingAlloc` deliberately does NOT override `GlobalAlloc::realloc`.
//! The trait's default `realloc` is alloc-new + copy + dealloc-old, so a
//! `String` doubling its buffer is charged for both buffers at once. That is
//! the honest model for a memory-limited cgroup: when the allocator cannot
//! extend a mapping in place — the common case once the heap is fragmented
//! by concurrent requests — both buffers really are resident, and it is the
//! moment the OOM killer fires. An in-place `realloc` would measure lower;
//! sizing a memory budget off the lower number is how you get OOMKilled.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use api::PodTraffic;
use chrono::NaiveDate;

struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn record_alloc(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    // Relaxed CAS loop: PEAK only ever climbs, and the measurement is
    // single-threaded under `alloc_lock()`, so this needs no ordering
    // beyond atomicity.
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            record_alloc(layout.size());
        }
        ptr
    }

    // realloc intentionally left to the trait default — see the module docs.
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// The counters are process-global, so measurements must not overlap.
/// `cargo test` runs test fns on parallel threads by default.
static ALLOC_LOCK: Mutex<()> = Mutex::new(());

fn alloc_lock() -> MutexGuard<'static, ()> {
    ALLOC_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Run `f` with the peak counter reset, returning (result, peak bytes above
/// the baseline live heap at entry).
fn measure_peak<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let out = f();
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(base);
    (out, peak)
}

/// A row shaped like production data, not like a minimal fixture.
///
/// Field widths are taken from a real `pod_traffic` row in the dev cluster:
/// a v4 UUID, a Deployment-generated pod name (`<deploy>-<rs hash>-<suffix>`),
/// a real namespace, an IPv4 pod address, numeric ports as text, and the
/// peer-identity columns populated (the common case once `crate::peer` has
/// resolved the row — an unresolved row is strictly cheaper, so this is the
/// conservative direction for sizing a budget).
fn representative_row(i: usize) -> PodTraffic {
    PodTraffic {
        uuid: format!("{:08x}-1f4b-4c7a-9e21-{:012x}", i, i),
        pod_name: Some(format!("kguardian-broker-7d9f8b6c5d-{i:05x}")),
        pod_namespace: Some("kguardian".to_string()),
        pod_ip: Some(format!("10.244.{}.{}", i % 256, (i / 256) % 256)),
        pod_port: Some("8080".to_string()),
        ip_protocol: Some("TCP".to_string()),
        traffic_type: Some(
            if i.is_multiple_of(2) {
                "INGRESS"
            } else {
                "EGRESS"
            }
            .to_string(),
        ),
        traffic_in_out_ip: Some(format!("10.244.{}.{}", (i / 7) % 256, (i / 11) % 256)),
        traffic_in_out_port: Some("443".to_string()),
        decision: Some("ALLOW".to_string()),
        time_stamp: NaiveDate::from_ymd_opt(2026, 9, 7)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap(),
        peer_kind: Some("pod".to_string()),
        peer_namespace: Some("kube-system".to_string()),
        peer_name: Some(format!("coredns-5d78c9869d-{i:05x}")),
        peer_uid: Some(format!("{:08x}-9a3c-4d1e-b8f2-{:012x}", i, i)),
        peer_workload_kind: Some("Deployment".to_string()),
        peer_workload_name: Some("coredns".to_string()),
        peer_resolved_at: Some(
            NaiveDate::from_ymd_opt(2026, 9, 7)
                .unwrap()
                .and_hms_opt(12, 0, 1)
                .unwrap(),
        ),
    }
}

const MIB: f64 = (1024 * 1024) as f64;

/// The hard cap `clamp_pod_traffic_limit` allows, i.e. the worst case a
/// single `GET /pod/traffic?limit=...` can ask for.
const HARD_CAP_ROWS: usize = 20_000;

#[test]
fn profile_pod_traffic_response_peak() {
    let _lock = alloc_lock();

    // Stage 1: the Vec<PodTraffic> alone — what diesel hands back after it
    // has converted every libpq row into Rust structs.
    let (rows, vec_peak) = measure_peak(|| {
        (0..HARD_CAP_ROWS)
            .map(representative_row)
            .collect::<Vec<_>>()
    });

    // Stage 2: serialise while the Vec is still alive. This is exactly what
    // actix does — `HttpResponseBuilder::json` calls `serde_json::to_string`,
    // growing one contiguous buffer by doubling, and the Vec is not dropped
    // until the handler returns. Both are resident at the same instant.
    let (body, both_peak) = measure_peak(|| serde_json::to_string(&rows).expect("serialise"));

    let body_len = body.len();
    let resident_per_row = vec_peak as f64 / HARD_CAP_ROWS as f64;
    let json_per_row = body_len as f64 / HARD_CAP_ROWS as f64;
    let combined_per_row = (vec_peak + both_peak) as f64 / HARD_CAP_ROWS as f64;

    println!("\n=== GET /pod/traffic?limit={HARD_CAP_ROWS} heap profile ===");
    println!(
        "Vec<PodTraffic> resident      : {:>9.2} MiB  ({resident_per_row:.1} B/row)",
        vec_peak as f64 / MIB
    );
    println!(
        "JSON body (final length)      : {:>9.2} MiB  ({json_per_row:.1} B/row)",
        body_len as f64 / MIB
    );
    println!(
        "serialise peak (body + Vec)   : {:>9.2} MiB",
        both_peak as f64 / MIB
    );
    println!(
        "PEAK in flight (Vec + serial.): {:>9.2} MiB  ({combined_per_row:.1} B/row)",
        (vec_peak + both_peak) as f64 / MIB
    );
    println!("=== end profile ===\n");

    drop(rows);

    // Regression guards, not exact assertions — allocator behaviour varies by
    // platform. What must hold is the shape of the finding that motivated the
    // budget: a single hard-cap read is tens of MiB, and the old "~350 B/row"
    // comment was optimistic by a wide margin.
    assert!(
        json_per_row > 350.0,
        "the pre-fix code comment claimed ~350 JSON B/row; measured {json_per_row:.1}. \
         If this ever drops below 350 the comment was right after all and \
         read_budget's constants should be re-derived."
    );
    assert!(
        combined_per_row > 1_000.0,
        "peak in-flight per row measured {combined_per_row:.1} B, expected >1 KiB; \
         re-derive read_budget::TRAFFIC_ROW_COST_BYTES"
    );
    assert!(
        vec_peak + both_peak > 30 * 1024 * 1024,
        "a hard-cap read should peak well above 30 MiB; measured {} MiB",
        (vec_peak + both_peak) as f64 / MIB
    );
}

/// Cost must be linear in row count — that is the assumption the budget's
/// `rows x bytes-per-row` estimate rests on. If serialisation were
/// superlinear the estimate would under-charge big reads exactly when it
/// matters most.
#[test]
fn cost_scales_linearly_with_row_count() {
    let _lock = alloc_lock();

    let mut per_row = Vec::new();
    for rows in [1_000usize, 5_000, 20_000] {
        let (v, vec_peak) = measure_peak(|| (0..rows).map(representative_row).collect::<Vec<_>>());
        let (_body, ser_peak) = measure_peak(|| serde_json::to_string(&v).expect("serialise"));
        drop(v);
        per_row.push((rows, (vec_peak + ser_peak) as f64 / rows as f64));
    }

    println!("\n=== per-row peak cost vs row count ===");
    for (rows, cost) in &per_row {
        println!("{rows:>6} rows : {cost:>8.1} B/row");
    }
    println!("=== end ===\n");

    // Compare the smallest and largest samples. Doubling-based growth makes
    // the per-row figure wobble (a buffer that just doubled is half empty),
    // so allow a generous band — this is a linearity check, not a tight bound.
    let small = per_row.first().expect("samples").1;
    let large = per_row.last().expect("samples").1;
    let ratio = large / small;
    assert!(
        (0.5..2.0).contains(&ratio),
        "per-row cost must be roughly constant across sizes; \
         {small:.1} B/row at 1k vs {large:.1} B/row at 20k (ratio {ratio:.2})"
    );
}

/// Before/after demonstration of the actual defect: **aggregate** peak heap
/// across concurrent reads, measured rather than calculated.
///
/// This is the assertion the incident needed and did not have. The per-request
/// profile above proves one read is expensive; this proves that nothing was
/// stopping N of them from being expensive at the same time, and that the
/// budget now does.
///
/// # Why it runs at 1/10 scale
///
/// Reproducing the real numbers means holding 32 x 37.8 MiB = 1.2 GB resident
/// in a test process, which is antisocial in CI and on a developer laptop. So
/// the demonstration uses `SCALED_ROWS` per read and a budget scaled by the
/// same factor. The property under test — aggregate peak is bounded by the
/// budget rather than by the pool size — is scale-invariant, and the ratio
/// between the two arms is what carries the evidence.
mod aggregate {
    use super::*;
    use api::{cost_kib, ReadBudget, TRAFFIC_ROW_COST_BYTES};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    /// Rows per simulated read. 1/10 of the 20000-row hard cap.
    const SCALED_ROWS: usize = 2_000;
    /// Concurrent readers — what `DB_POOL_MAX_SIZE=32` admitted.
    const POOL_MAX_SIZE: usize = 32;
    /// Budget for the "after" arm: 1/10 of the 256 MiB production default,
    /// matching the 1/10 row scale.
    const SCALED_BUDGET_KIB: u32 = 25 * 1024;

    /// One read's full response cycle: materialise the rows, serialise them,
    /// then hold both until every other reader has done the same. The barrier
    /// is what makes the peak *aggregate* — without it the OS scheduler would
    /// let readers finish one at a time and the sum would never be resident
    /// at once, which is exactly the mistake that made 32 concurrent reads
    /// look survivable.
    fn one_read(barrier: &Barrier) {
        let rows: Vec<PodTraffic> = (0..SCALED_ROWS).map(representative_row).collect();
        let body = serde_json::to_string(&rows).expect("serialise");
        barrier.wait();
        drop(body);
        drop(rows);
    }

    fn run_concurrent(readers: usize, budget: Option<ReadBudget>) -> usize {
        let barrier = Arc::new(Barrier::new(readers));
        let budget = budget.map(Arc::new);

        let (_, peak) = measure_peak(|| {
            std::thread::scope(|s| {
                for _ in 0..readers {
                    let barrier = Arc::clone(&barrier);
                    let budget = budget.clone();
                    s.spawn(move || match budget {
                        Some(b) => {
                            // Admission control, using the real ReadBudget.
                            // A shed reader still has to clear the barrier or
                            // the admitted ones would block forever — that is
                            // a test artifact, not a production behaviour:
                            // in the broker a shed read returns 503 and holds
                            // no memory at all, which is the point.
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_time()
                                .build()
                                .expect("runtime");
                            let cost = cost_kib(SCALED_ROWS as i64, TRAFFIC_ROW_COST_BYTES);
                            match rt.block_on(b.acquire(cost)) {
                                Ok(_permit) => one_read(&barrier),
                                Err(_shed) => {
                                    barrier.wait();
                                }
                            }
                        }
                        None => one_read(&barrier),
                    });
                }
            });
        });
        peak
    }

    #[test]
    fn budget_bounds_aggregate_peak_across_concurrent_reads() {
        let _lock = alloc_lock();

        // BEFORE: nothing but DB_POOL_MAX_SIZE bounds concurrency.
        let before = run_concurrent(POOL_MAX_SIZE, None);

        // AFTER: the same 32 offered reads, admitted through the budget.
        // Zero wait so shed readers fail fast instead of queueing — the
        // measurement is of simultaneous residency, not throughput.
        let after = run_concurrent(
            POOL_MAX_SIZE,
            Some(ReadBudget::with_budget_kib(
                SCALED_BUDGET_KIB,
                Duration::from_millis(0),
            )),
        );

        let scale = (20_000 / SCALED_ROWS) as f64;
        println!("\n=== aggregate peak: {POOL_MAX_SIZE} concurrent reads ===");
        println!(
            "BEFORE (pool-bounded only) : {:>8.1} MiB   [~{:.0} MiB at full 20000-row scale]",
            before as f64 / MIB,
            (before as f64 / MIB) * scale
        );
        println!(
            "AFTER  (memory-bounded)    : {:>8.1} MiB   [~{:.0} MiB at full 20000-row scale]",
            after as f64 / MIB,
            (after as f64 / MIB) * scale
        );
        println!(
            "budget                     : {:>8.1} MiB   [{} MiB at full scale]",
            SCALED_BUDGET_KIB as f64 / 1024.0,
            (SCALED_BUDGET_KIB / 1024) * scale as u32
        );
        println!(
            "reduction                  : {:>8.1}x",
            before as f64 / after as f64
        );
        println!("=== end ===\n");

        // The "before" arm must reproduce the hazard: 32 concurrent reads
        // scale to more than the 656 MiB of real headroom measured in the
        // cluster. If this ever stops holding, the defect is gone by some
        // other route and this whole module should be re-justified.
        let before_at_full_scale_mib = (before as f64 / MIB) * scale;
        assert!(
            before_at_full_scale_mib > 656.0,
            "the unbounded arm must exceed the 656 MiB of measured headroom to \
             reproduce the OOMKill; got {before_at_full_scale_mib:.0} MiB"
        );

        // The "after" arm must fit the budget, with slack for the serialise
        // transient of the admitted readers and per-thread stacks.
        let budget_mib = SCALED_BUDGET_KIB as f64 / 1024.0;
        assert!(
            (after as f64 / MIB) < budget_mib * 1.5,
            "budgeted aggregate peak {:.1} MiB must stay near the {budget_mib:.1} MiB budget",
            after as f64 / MIB
        );

        assert!(
            after < before,
            "the budget must actually reduce aggregate peak: before {} MiB, after {} MiB",
            before as f64 / MIB,
            after as f64 / MIB
        );
    }
}
