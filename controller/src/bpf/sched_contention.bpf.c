// Scheduler-contention probe: per-cgroup run-queue latency histogram
// plus a victim<-culprit preemption-pair matrix.
//
// Design: docs/design/compute-contention-monitoring.md, D4. The shape
// is Netflix's runq.latency + sched.switch.out split, with the bcc
// runqlat fixes (re-timestamp a preempted `prev`; latest wakeup wins)
// and the corrections the olga-mir reference needed: typed BPF_PROG()
// arguments instead of a hand-cast ctx, a sched_wakeup_new hook so
// forked tasks are not orphaned, a sched_process_exit hook so dead pids
// are not orphaned, and an overflow bucket that stays an overflow
// bucket.
//
// No ring buffer. Everything is aggregated in the maps and read by
// userspace (controller/src/contention.rs) once per sample interval,
// which diffs against its previous read. Nothing here is ever zeroed
// by the kernel side.
//
// Programs are `tp_btf/` only. A raw_tp fallback was considered and
// dropped: every BPF_CORE_READ below is a CO-RE relocation that libbpf
// resolves against /sys/kernel/btf/vmlinux at load time, so a kernel
// without BTF cannot load a raw_tp build of this file either — the
// fallback could never succeed. Userspace checks for vmlinux BTF and
// reports contention_loaded=false without it.
//
// Portability of the atomics: build.rs compiles this file with
// -mcpu=v2 so `__sync_fetch_and_add` lowers to the legacy BPF_XADD
// (`lock *(u64 *)(r) += r`) rather than v3's BPF_ATOMIC|BPF_FETCH,
// which the verifier rejects before 5.12 and the arm64 JIT before 5.18.
// None of the adds below use the returned value — that is what makes
// the v2 lowering possible; keep it that way.
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
//
// No registration generation is folded into this key, unlike inode_num
// (helper.h KG_GEN_SHIFT). A cgroup v2 id IS kernfs_node.id, which on
// 64-bit kernels is `ino | (generation << 32)`: the kernfs idr bumps the
// generation every time an inode number is recycled (kernfs_id_gen /
// kernfs_gen), so a replacement pod landing on a reused ino still gets
// a different u64 here and cannot inherit its predecessor's rows. The
// design doc's "same generation discipline" is therefore satisfied by
// the key itself.
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

// {victim, bucket} -> count. Exact (not LRU) so the histogram is never
// silently eroded: 65536 rows = 2730 tracked cgroups x 24 buckets, ~2 MB.
// Userspace frees a victim's rows on untrack and sweeps any stragglers
// on each snapshot. If the map does fill, bpf_map_update_elem fails and
// the miss is counted in probe_stats so the loss is a visible number
// rather than a quietly flat histogram.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
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

// Update-failure counters, read alongside map occupancy every sample.
//   [0] runq_hist inserts that failed (map full)
//   [1] pair inserts that failed (LRU eviction itself never fails; this
//       only moves when the LRU cannot evict, e.g. all rows hot on the
//       same CPU)
#define KG_STAT_HIST_UPDATE_FAILURES 0
#define KG_STAT_PAIR_UPDATE_FAILURES 1
#define KG_STAT_COUNT 2

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, KG_STAT_COUNT);
    __type(key, u32);
    __type(value, u64);
} probe_stats SEC(".maps");

static __always_inline void stat_inc(u32 idx)
{
    u64 *v = bpf_map_lookup_elem(&probe_stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

// task_struct.state was renamed to __state (and narrowed from long to
// unsigned int) in 5.14. Both spellings are reached through local CO-RE
// shadow types rather than through whatever the bundled vmlinux.h
// happens to call the field, so this compiles and relocates the same
// way whichever vmlinux.h generation is checked in.
// bpf_core_field_exists() resolves to a constant at load time; libbpf
// leaves the other branch as a poisoned-but-dead instruction that the
// verifier prunes.
struct task_struct___pre_5_14
{
    volatile long state;
} __attribute__((preserve_access_index));

struct task_struct___post_5_14
{
    unsigned int __state;
} __attribute__((preserve_access_index));

static __always_inline u32 task_state(struct task_struct *t)
{
    struct task_struct___post_5_14 *tn = (void *)t;
    if (bpf_core_field_exists(tn->__state))
        return BPF_CORE_READ(tn, __state);

    struct task_struct___pre_5_14 *to = (void *)t;
    return (u32)BPF_CORE_READ(to, state);
}

// True when the task is currently executing on a CPU. `on_cpu` exists
// only under CONFIG_SMP; on a UP kernel nothing can be woken while it
// runs in the sense that matters here, so the answer is "no".
static __always_inline bool task_on_cpu(struct task_struct *t)
{
    if (!bpf_core_field_exists(t->on_cpu))
        return false;
    return BPF_CORE_READ(t, on_cpu) != 0;
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

// Latency (ns) -> histogram bucket. Bucket b covers [2^b, 2^(b+1)) us;
// a sub-microsecond latency (lat_us == 0) is folded into bucket 0, which
// is only reachable when probe_config[0] is below 1000 ns — at the
// default 100 us floor bucket 0 is never written. Anything >= 2^23 us
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

// Shared body: sched_wakeup / sched_wakeup_new.
//
// What the tracepoint actually means, from kernel/sched/core.c:
//
//  - A task that is already runnable and WAITING (on the rq, not on a
//    CPU) never gets a second sched_wakeup: ttwu_state_match() rejects a
//    target whose state is already TASK_RUNNING. So there is no
//    "woken again while queued" case to protect a timestamp against.
//
//  - A task that is RUNNING on a CPU does get sched_wakeup: it has set
//    TASK_INTERRUPTIBLE ahead of schedule() and a wakeup landed in the
//    window (ttwu_runnable() -> ttwu_do_wakeup() whenever
//    task_on_rq_queued(); also the p == current self-wake path). It
//    then carries on running, never switches in, and an entry stamped
//    now would be popped by its NEXT switch-in — after it has run,
//    blocked for real and been woken again — charging the run and the
//    sleep to run-queue latency. With a keep-oldest policy that stale
//    stamp also survived the genuine wakeup, and the result was a
//    phantom multi-second p99 in the victim's histogram and a bogus
//    pair. Hence: ignore wakeups of an on-CPU task, and let the latest
//    wakeup win (BPF_ANY, bcc runqlat semantics).
//
// Not measured, same as bcc: wake-list IPI latency. sched_wakeup fires
// on the CPU that finally enqueues the task (ttwu_do_activate), so time
// spent queued on another CPU's wake_list before that is invisible
// here. It is normally a few microseconds and not a neighbour effect.
static __always_inline int handle_wakeup(struct task_struct *p)
{
    u32 pid = BPF_CORE_READ(p, pid);
    if (pid == 0)
        return 0;
    if (task_on_cpu(p))
        return 0;

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&runq_enqueued, &pid, &ts, BPF_ANY);
    return 0;
}

// Shared body: sched_switch.
static __always_inline int handle_switch(bool preempt, struct task_struct *prev,
                                         struct task_struct *next)
{
    u64 now = bpf_ktime_get_ns();

    // A prev that stays on the run queue was not blocked: its wait
    // starts now. Two ways that happens, both from __schedule():
    //   - prev is still TASK_RUNNING: ordinary preemption (tick, wakeup
    //     preemption) — the bcc runqlat check;
    //   - `preempt` is set: prev was preempted between
    //     set_current_state(!RUNNING) and schedule(), so its state is
    //     not RUNNING yet __schedule() skipped deactivate_task() and it
    //     is still queued. A state-only check misses exactly this case.
    // Preemption IS the noisy-neighbour mechanism, so both count. The
    // `preempt` flag is the tracepoint's first argument on every kernel
    // this probe supports.
    u32 prev_pid = BPF_CORE_READ(prev, pid);
    if (prev_pid != 0 && (preempt || task_state(prev) == TASK_RUNNING))
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
    else
        stat_inc(KG_STAT_HIST_UPDATE_FAILURES);

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
    else
        stat_inc(KG_STAT_PAIR_UPDATE_FAILURES);

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

// ---- tp_btf programs -----------------------------------------------
//
// Argument lists mirror the tracepoint prototypes in
// include/trace/events/sched.h, truncated to what every supported
// kernel has. A tp_btf program that names MORE arguments than the
// running kernel's tracepoint carries fails verification, so:
//   - sched_switch grew a 4th `unsigned int prev_state` in 5.18: not
//     declared; prev's state is read off the task instead.
//   - sched_process_exit grew a 2nd `bool group_dead` in 6.16: never
//     declare it.

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
    return handle_switch(preempt, prev, next);
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(tp_btf_sched_process_exit, struct task_struct *p)
{
    return handle_exit(p);
}

char LICENSE[] SEC("license") = "GPL";
