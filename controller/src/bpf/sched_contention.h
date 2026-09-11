// Shared layouts for the scheduler-contention probe.
//
// Every struct here is a BPF map key or value, so it is also a wire
// format between sched_contention.bpf.c and controller/src/contention.rs.
// The Rust side reads these back as raw native-endian bytes at the
// offsets the C layout implies; change a field here and the Rust
// parsers (`hist_key_from_bytes`, `pair_key_from_bytes`,
// `pair_value_from_bytes`) must change with it. Sizes are pinned by the
// _Static_asserts in sched_contention.bpf.c.
#ifndef __KG_SCHED_CONTENTION_H
#define __KG_SCHED_CONTENTION_H

// Run-queue latency histogram: bucket b counts wake-to-run latencies in
// [2^b, 2^(b+1)) microseconds. Bucket 23 is the overflow bucket
// (>= 2^23 us, ~8.4 s) and is reported to userspace as a count, never
// folded into a finite maximum — the reference implementation clamped
// its overflow to a finite `le` and produced a phantom 8 s p99.
#define KG_RUNQ_HIST_BUCKETS 24
#define KG_RUNQ_OVERFLOW_BUCKET (KG_RUNQ_HIST_BUCKETS - 1)

struct runq_hist_key
{
    __u64 cgroup_id; // victim (the task that waited)
    __u32 bucket;    // 0..KG_RUNQ_OVERFLOW_BUCKET
    __u32 pad;       // always 0; keeps the key a clean 16 bytes
};

// Who was on the CPU when the victim finally got it. `culprit` is 0
// for the idle task and for kernel threads (PF_KTHREAD); userspace
// classifies 0 as `kernel`.
struct pair_key
{
    __u64 victim;
    __u64 culprit;
};

struct pair_value
{
    __u64 count;   // number of switches victim <- culprit
    __u64 wait_ns; // summed run-queue wait of those switches
};

#endif // __KG_SCHED_CONTENTION_H
