// Scheduler-contention probe: per-cgroup run-queue latency histogram
// plus a victim<-culprit preemption-pair matrix.
//
// Design: docs/design/compute-contention-monitoring.md, D4. The shape
// is Netflix's runq.latency + sched.switch.out split, with the bcc
// runqlat fix (re-timestamp a preempted `prev`) and the corrections the
// olga-mir reference needed: typed BPF_PROG() arguments instead of a
// hand-cast ctx, a sched_wakeup_new hook so forked tasks are not
// orphaned, a sched_process_exit hook so dead pids are not orphaned,
// and an overflow bucket that stays an overflow bucket.
//
// No ring buffer. Everything is aggregated in the maps and read by
// userspace (controller/src/contention.rs) once per sample interval,
// which diffs against its previous read. Nothing here is ever zeroed
// by the kernel side.
//
// Two program families carry the same bodies: `tp_btf/` (typed,
// fastest, needs CONFIG_DEBUG_INFO_BTF) and `raw_tp/` (works on any
// kernel with raw tracepoints). Userspace autoloads exactly one family;
// the bodies use only BPF_CORE_READ so they verify under both — in a
// raw_tp program `prev`/`next` are untrusted pointers and may NOT be
// dereferenced directly, so do not "simplify" a BPF_CORE_READ into a
// plain `->` even though the tp_btf verifier would accept it.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sched_contention.h"

_Static_assert(sizeof(struct runq_hist_key) == 16, "runq_hist_key is 16 bytes on the wire");
_Static_assert(sizeof(struct pair_key) == 16, "pair_key is 16 bytes on the wire");
_Static_assert(sizeof(struct pair_value) == 16, "pair_value is 16 bytes on the wire");

#define TASK_RUNNING 0
#define PF_KTHREAD 0x00200000

// Cgroup ids kguardian wants a histogram for (the containers of pods
// it tracks, minus `kguardian.dev/compute: off`). Victim filter only:
// culprits are recorded raw, since "starved by kubelet" is a legitimate
// answer. The value is a flags word written by userspace; the probe
// tests presence only.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, u32);
} tracked_cgroups SEC(".maps");

// pid -> ktime it became runnable. Plain HASH, not LRU: Netflix
// measured LRU 40-50 ns slower per op and chose a large plain hash.
// Entries are popped on switch-in and deleted on exit, so steady-state
// occupancy is "tasks currently waiting for a CPU"; userspace exports
// the key count so a leak shows up as a number.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);
    __type(value, u64);
} runq_enqueued SEC(".maps");

// {victim, bucket} -> count. Exact (not LRU): tracked cgroups x 24.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct runq_hist_key);
    __type(value, u64);
} runq_hist SEC(".maps");

// {victim, culprit} -> {count, wait_ns}. LRU so neighbour churn evicts
// safely; userspace treats a key that vanishes and comes back as a
// fresh baseline rather than a negative delta.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct pair_key);
    __type(value, struct pair_value);
} pair SEC(".maps");

// [0] = minimum run-queue latency (ns) worth recording. Named
// probe_config because vmlinux.h already typedefs `config`. Written by
// userspace after load and before attach, so no event ever sees a zero.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} probe_config SEC(".maps");

// task_struct.state was renamed to __state (and narrowed to unsigned
// int) in 5.14. Our vmlinux.h predates that, so the new name is reached
// through a local CO-RE shadow type; bpf_core_field_exists() picks the
// live one and libbpf leaves the other branch as a poisoned-but-dead
// instruction the verifier prunes.
struct task_struct___post_5_14
{
    unsigned int __state;
} __attribute__((preserve_access_index));

static __always_inline u32 task_state(struct task_struct *t)
{
    struct task_struct___post_5_14 *tn = (void *)t;
    if (bpf_core_field_exists(tn->__state))
        return BPF_CORE_READ(tn, __state);
    return (u32)BPF_CORE_READ(t, state);
}

// cgroup v2 id via the probe-read path: task->cgroups->dfl_cgrp->kn->id.
// Not the bpf_rcu_read_lock kfunc route, which needs >= 6.2 and is
// what made the reference 6.x-only. Costs ~20-30 ns more; works on
// every kernel that satisfies kguardian's CO-RE requirement (>= 5.8,
// where kernfs_node.id is already a plain u64).
static __always_inline u64 task_cgroup_id(struct task_struct *t)
{
    return BPF_CORE_READ(t, cgroups, dfl_cgrp, kn, id);
}

// floor(log2(v)) for v > 0, branch-free. clang has no BPF lowering for
// __builtin_clzll, so this is the bcc log2l shape.
static __always_inline u32 log2_u64(u64 v)
{
    u32 r = 0;
    u32 shift;

    shift = (v > 0xFFFFFFFFULL) << 5;
    v >>= shift;
    r |= shift;
    shift = (v > 0xFFFF) << 4;
    v >>= shift;
    r |= shift;
    shift = (v > 0xFF) << 3;
    v >>= shift;
    r |= shift;
    shift = (v > 0xF) << 2;
    v >>= shift;
    r |= shift;
    shift = (v > 0x3) << 1;
    v >>= shift;
    r |= shift;
    r |= (u32)(v >> 1);
    return r;
}

// Latency (ns) -> histogram bucket. Sub-microsecond latencies land in
// bucket 0 (only reachable when config[0] < 1000); anything >= 2^23 us
// lands in the overflow bucket.
static __always_inline u32 runq_bucket(u64 lat_ns)
{
    u64 lat_us = lat_ns / 1000;
    if (lat_us == 0)
        return 0;
    u32 b = log2_u64(lat_us);
    if (b > KG_RUNQ_OVERFLOW_BUCKET)
        b = KG_RUNQ_OVERFLOW_BUCKET;
    return b;
}

// Shared body: sched_wakeup / sched_wakeup_new. BPF_NOEXIST keeps the
// OLDEST timestamp if the task is already waiting (woken again while
// still on the queue), which is the latency the task actually saw.
static __always_inline int handle_wakeup(struct task_struct *p)
{
    u32 pid = BPF_CORE_READ(p, pid);
    if (pid == 0)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&runq_enqueued, &pid, &ts, BPF_NOEXIST);
    return 0;
}

// Shared body: sched_switch.
static __always_inline int handle_switch(struct task_struct *prev, struct task_struct *next)
{
    u64 now = bpf_ktime_get_ns();

    // A prev that is still TASK_RUNNING was preempted, not blocked: it
    // goes straight back on the run queue and its wait starts now.
    // This is the noisy-neighbour case and the line Netflix's published
    // snippet omits (bcc runqlat has it).
    u32 prev_pid = BPF_CORE_READ(prev, pid);
    if (prev_pid != 0 && task_state(prev) == TASK_RUNNING)
        bpf_map_update_elem(&runq_enqueued, &prev_pid, &now, BPF_ANY);

    u32 next_pid = BPF_CORE_READ(next, pid);
    if (next_pid == 0)
        return 0;

    u64 *tsp = bpf_map_lookup_elem(&runq_enqueued, &next_pid);
    if (!tsp)
        return 0;
    u64 ts = *tsp;
    bpf_map_delete_elem(&runq_enqueued, &next_pid);

    if (now < ts)
        return 0;
    u64 lat = now - ts;

    // Victim filter first: everything that is not a tracked cgroup
    // returns before any further map work.
    u64 victim = task_cgroup_id(next);
    if (!bpf_map_lookup_elem(&tracked_cgroups, &victim))
        return 0;

    u32 zero = 0;
    u64 *min_ns = bpf_map_lookup_elem(&probe_config, &zero);
    if (min_ns && lat < *min_ns)
        return 0;

    struct runq_hist_key hk = {
        .cgroup_id = victim,
        .bucket = runq_bucket(lat),
        .pad = 0,
    };
    u64 *cnt = bpf_map_lookup_elem(&runq_hist, &hk);
    if (!cnt)
    {
        // First sighting of this {victim, bucket}. Insert a zero and
        // re-lookup so a concurrent CPU racing on the same key cannot
        // lose either increment (the raced update fails with -EEXIST
        // and both fall through to the atomic add).
        u64 init = 0;
        bpf_map_update_elem(&runq_hist, &hk, &init, BPF_NOEXIST);
        cnt = bpf_map_lookup_elem(&runq_hist, &hk);
    }
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    // Culprit: whoever had the CPU. Idle (pid 0) and kernel threads are
    // 0, which userspace classifies as `kernel`.
    u64 culprit = 0;
    if (prev_pid != 0 && !(BPF_CORE_READ(prev, flags) & PF_KTHREAD))
        culprit = task_cgroup_id(prev);

    struct pair_key pk = {
        .victim = victim,
        .culprit = culprit,
    };
    struct pair_value *pv = bpf_map_lookup_elem(&pair, &pk);
    if (!pv)
    {
        struct pair_value init = {.count = 0, .wait_ns = 0};
        bpf_map_update_elem(&pair, &pk, &init, BPF_NOEXIST);
        pv = bpf_map_lookup_elem(&pair, &pk);
    }
    if (pv)
    {
        __sync_fetch_and_add(&pv->count, 1);
        __sync_fetch_and_add(&pv->wait_ns, lat);
    }

    return 0;
}

// Shared body: sched_process_exit. Without this a task that is woken
// and then exits before it is ever switched in (or whose final
// switch-in the probe missed) leaves its pid behind until the number is
// recycled — the leak behind the reference's phantom p99.
static __always_inline int handle_exit(struct task_struct *p)
{
    u32 pid = BPF_CORE_READ(p, pid);
    if (pid == 0)
        return 0;
    bpf_map_delete_elem(&runq_enqueued, &pid);
    return 0;
}

// ---- tp_btf family -------------------------------------------------
//
// Argument lists mirror the tracepoint prototypes in
// include/trace/events/sched.h. sched_switch grew a fourth `prev_state`
// argument in 5.18; it is deliberately NOT declared here because a
// tp_btf program that names more arguments than the kernel's tracepoint
// has fails verification on older kernels. prev's state is read off the
// task instead (bcc runqlat does the same).

SEC("tp_btf/sched_wakeup")
int BPF_PROG(tp_btf_sched_wakeup, struct task_struct *p)
{
    return handle_wakeup(p);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(tp_btf_sched_wakeup_new, struct task_struct *p)
{
    return handle_wakeup(p);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(tp_btf_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    return handle_switch(prev, next);
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(tp_btf_sched_process_exit, struct task_struct *p)
{
    return handle_exit(p);
}

// ---- raw_tp family -------------------------------------------------
//
// Same bodies. libbpf auto-attaches SEC("raw_tp/<name>") by name.

SEC("raw_tp/sched_wakeup")
int BPF_PROG(raw_tp_sched_wakeup, struct task_struct *p)
{
    return handle_wakeup(p);
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(raw_tp_sched_wakeup_new, struct task_struct *p)
{
    return handle_wakeup(p);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(raw_tp_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    return handle_switch(prev, next);
}

SEC("raw_tp/sched_process_exit")
int BPF_PROG(raw_tp_sched_process_exit, struct task_struct *p)
{
    return handle_exit(p);
}

char LICENSE[] SEC("license") = "GPL";
