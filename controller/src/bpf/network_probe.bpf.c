#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "helper.h"

// TCP states (include/net/tcp_states.h). Frozen values: tcp_set_state
// carries BUILD_BUG_ONs pinning each TCP_* to the BPF_TCP_* UAPI enum
// precisely so BPF programs can depend on them.
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3

// Wire struct shared with userspace (controller/src/network.rs,
// NetworkEventData). The ring-buffer callback in controller/src/bpf.rs
// reinterprets the raw bytes with a pointer cast, so ANY change to
// field order, width or padding here is silent memory corruption unless
// the Rust mirror changes with it. The _Static_asserts below and the
// layout tests in network.rs pin both sides to the same numbers.
//
// Addresses are 16 bytes, IPv4 carried v4-mapped — see IPV6_ADDR_LEN in
// helper.h. Fields are ordered so the struct has no implicit padding;
// `_pad` is explicit and named so designated initialisers zero it
// (unnamed padding bytes are not guaranteed zeroed, and would leak
// uninitialised ring-buffer memory to userspace).
struct network_event_data
{
    __u64 inum;                  // 0
    __u8 saddr[IPV6_ADDR_LEN];   // 8
    __u8 daddr[IPV6_ADDR_LEN];   // 24
    __u16 sport;                 // 40
    __u16 dport;                 // 42
    __u16 kind;                  // 44 - 2-> Ingress, 1- Egress, 3-> UDP
    __u16 _pad;                  // 46
};

_Static_assert(sizeof(struct network_event_data) == 48,
               "network_event_data layout changed; update NetworkEventData in network.rs");
_Static_assert(__builtin_offsetof(struct network_event_data, saddr) == 8, "saddr offset");
_Static_assert(__builtin_offsetof(struct network_event_data, daddr) == 24, "daddr offset");
_Static_assert(__builtin_offsetof(struct network_event_data, kind) == 44, "kind offset");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    // 512KB ring buffer. Bumped from 256KB when addresses widened to 16
    // bytes: events doubled 24 -> 48 bytes, so the old size held half as
    // many in-flight events and dropped them under burst.
    __uint(max_entries, 512 * 1024);
} network_events SEC(".maps");

// Connection tracking to reduce duplicate events
// Uses 4-tuple (no source port) to handle ephemeral port rotation
//
// `generation` is part of the key for the reason spelled out at
// KG_GEN_SHIFT in helper.h, and it is the field this struct was missing
// while the syscall probe's equivalent key already had it. `connections`
// below is node-wide, nothing deletes from it when a pod dies, and every
// hit refreshes last_seen so a hot entry never falls out of the LRU. A
// replacement pod that reused a dead pod's netns inode — routine on
// EKS/VPC-CNI, where inode numbers and pod IPs both recycle from
// node-local pools — therefore hashed straight onto its predecessor's
// entry and was told "already reported, stay quiet" for the rest of its
// life. DNS was the visible casualty: it is one tuple per pod, so a
// single suppressed key meant the pod produced no UDP rows at all and
// its generated policy silently omitted the DNS egress rule.
struct conn_key {
    __u64 inum;                  // Network namespace inode
    __u8 saddr[IPV6_ADDR_LEN];   // Source IP (v4-mapped when IPv4)
    __u8 daddr[IPV6_ADDR_LEN];   // Destination IP (v4-mapped when IPv4)
    __u16 dport;                 // Destination port
    __u8 protocol;               // 1=TCP, 2=UDP
    __u8 direction;              // 1=Egress, 2=Ingress
    __u32 generation;            // Registration generation for `inum`. Also
                                 // occupies what would otherwise be implicit
                                 // tail padding: hash map keys are compared
                                 // byte-wise, and only *named* members are
                                 // guaranteed zeroed by a designated
                                 // initialiser.
    // NOTE: sport (source port) intentionally omitted to handle ephemeral ports
};

_Static_assert(sizeof(struct conn_key) == 48, "conn_key must have no implicit padding");

struct conn_state {
    __u64 first_seen;
    __u64 last_seen;
    __u32 event_count;
};

// Per-flow-class dedup so each observed flow crosses into userspace once.
//
// INVARIANT: an entry here means "userspace HAS this flow". It is
// written only by mark_connection_seen, and only after a successful
// bpf_ringbuf_submit — never before. connection_already_seen is a pure
// lookup and inserts nothing, so there is no state to unwind on a
// failed publish and no ordering for a future emitter to get wrong.
//
// Marking before publishing is what this replaced, and the failure it
// produced was not a dropped packet but a dropped flow CLASS: conn_key
// carries no source port, so one entry marked-but-never-delivered
// silences every later connection matching (netns, saddr, daddr, dport,
// proto, direction). Nothing recovers it either. This is a common LRU
// with no TTL and no reaper, so eviction only happens under allocation
// pressure; a node that never approaches 65536 keys never evicts, and a
// lookup marks a node referenced, so a recurring suppressed flow keeps
// refreshing its own entry and is evicted last.
//
// helper.h records what that costs in practice: a pod silenced for a
// single-tuple class like `pod -> kube-dns:53` yields a policy with no
// DNS egress rule, which breaks the workload the moment it is enforced.
//
// netpolicy_drop.bpf.c uses the same publish-then-mark ordering (it sets
// established = 1 after its submit). Any new emitter here must too.
//
// CHOOSING A PATTERN FOR A NEW PROBE. There are two correct shapes in
// this tree and they are not interchangeable:
//
//   1. Publish, then mark (here, and netpolicy_drop). Use this when the
//      claim cannot be made atomically. Costs a duplicate event when two
//      CPUs race the same new key, which userspace and the broker both
//      dedup. Cannot lose a flow, because nothing is marked until it has
//      been delivered.
//
//   2. Claim atomically, then unwind on failure (syscall.bpf.c). Use
//      this only with BPF_NOEXIST, which is a test-and-set: exactly one
//      CPU wins the insert, so the delete on a failed reserve unwinds an
//      entry that invocation definitively owns. Suppresses the duplicate
//      that (1) accepts.
//
// Mixing them is what produced the bug this comment exists for: the old
// code here marked first but claimed with a non-atomic lookup followed
// by BPF_ANY, so two CPUs could both believe they had inserted, and the
// unwind could then delete an entry belonging to the other.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536); // Track up to 64K active connections
    __type(key, struct conn_key);
    __type(value, struct conn_state);
} connections SEC(".maps");

// True when this flow class has already been published to userspace.
//
// A miss does NOT insert; that is mark_connection_seen's job, and it
// runs only after bpf_ringbuf_submit, which is what makes "marked but
// never delivered" unrepresentable rather than merely avoided.
// netpolicy_drop.bpf.c already had this shape (it sets established = 1
// after its submit); this is the same property.
//
// Not otherwise side-effect free: the hit path still refreshes
// last_seen and bumps event_count, which is the bookkeeping the old
// combined helper did in its else branch. "Lookup" here means it does
// not CLAIM the key, not that it does not write.
//
// The ordering matters because the alternative was live: marking first
// and un-marking on a failed reserve leaves a window where a second CPU
// sees the mark, drops its own event, and then the first CPU deletes
// the entry. Marking after publish has no such window.
static __always_inline bool connection_already_seen(struct conn_key *key)
{
    struct conn_state *state = bpf_map_lookup_elem(&connections, key);
    if (!state)
        return false;

    state->last_seen = bpf_ktime_get_ns();
    state->event_count++;
    return true;
}

// Record that this flow class has been published. Call ONLY after a
// successful bpf_ringbuf_submit.
//
// This ordering trades duplicates for never losing a flow, and the trade
// is sound because the harms are wildly asymmetric — not because
// duplicates are free. A lost class is unrecoverable and silently wrong:
// conn_key has no source port, so one missing entry silences every later
// connection matching (netns, saddr, daddr, dport, proto, direction),
// and this is a common LRU with no TTL that never reclaims it on a node
// below 65536 keys.
//
// A duplicate is bounded and recoverable, but be precise about why. For
// the GENERATED POLICY it is genuinely idempotent: the output is a set
// of rules, so repeat observations of a flow class collapse into one.
// Everything before that point is best-effort rather than idempotent:
//   - pod_traffic has no unique constraint on its content columns (only
//     `uuid VARCHAR PRIMARY KEY`, and the controller mints a fresh uuid
//     per event), so the database is no backstop.
//   - TRAFFIC_CACHE in network.rs is check-then-act across an await
//     (contains_key at :341, insert at :366), tracked as #1504.
//   - add.rs dedups per batch and against a pre-commit read, so two
//     concurrent in-flight POSTs can both miss; its own comment at :135
//     names the cost, which is a double insert AND a double audit fire
//     that inflates verdict and flow counts.
// So a duplicate that slips every layer costs a spare row and one extra
// evaluator round trip. Bounded, pre-existing, and far cheaper than a
// permanently silenced flow class.
//
// Do NOT upgrade this to "idempotent by construction" or to "the caches
// dedup it". Both are the kind of claim someone later leans on while
// removing a layer.
//
// Note the window is lookup-miss to mark-visible across all CPUs, so a
// high-rate flow class can produce several duplicates rather than one.
// Bounded, sub-microsecond, and absorbed by the same idempotency.
//
// One caveat if conn_state ever grows a consumer: when two CPUs both
// mark, the second write is a fresh struct under BPF_ANY, so first_seen
// and event_count reset. They are internal to this dedup map today, so
// nothing observes it, but they are not reliable as flow duration or
// occurrence counts without changing this to an update-in-place.
static __always_inline void mark_connection_seen(struct conn_key *key)
{
    __u64 now = bpf_ktime_get_ns();
    struct conn_state new_state = {
        .first_seen = now,
        .last_seen = now,
        .event_count = 1,
    };
    bpf_map_update_elem(&connections, key, &new_state, BPF_ANY);
}

// Context for TCP connect/accept kprobe/kretprobe pairs
struct tcp_connect_ctx {
    struct sock *sk;
    __u64 inum;
    __u32 generation; // carried alongside inum so the kretprobe can build the
                      // same generation-qualified conn_key as every other
                      // emitter; the accepted socket is not available on entry
};

// Use LRU map to automatically evict stale entries if thread dies
// Use PER_CPU to eliminate lock contention on multi-core systems
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct tcp_connect_ctx);
} tcp_ctx SEC(".maps");

// Shared body for the two UDP egress entry points below.
//
// udp_sendmsg only ever sees AF_INET sockets plus the v4-mapped sends
// udpv6_sendmsg delegates back to it; native IPv6 UDP — most
// importantly a DNS query to an IPv6 CoreDNS clusterIP — goes through
// udpv6_sendmsg and never reaches the v4 hook. Both hooks funnel here.
//
// skip_v4_mapped is set by the v6 hook: a v4-mapped destination is
// about to be handed to udp_sendmsg by the kernel, where the v4 hook
// records it, so skipping here keeps each send tracked exactly once.
//
// `msg` is not decoration either — for an unconnected socket it holds
// the only copy of the destination. See read_msghdr_dest in helper.h.
static __always_inline int handle_udp_send(struct sock *sk, struct msghdr *msg, bool skip_v4_mapped)
{

    // Validate socket and get inode - single lookup
    __u64 inum = 0;
    __u32 generation = 0;
    if (!get_and_validate_inum(sk, &inum, &generation))
        return 0;

    // Read socket common structure once (batch read) - ports only; the
    // addresses come from read_sock_addrs, which relocates the v6 fields
    // properly. See helper.h.
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    // Resolve addresses and reject unsupported families. This path had
    // NO family check before IPv6 support: an AF_INET6 socket leaves
    // skc_rcv_saddr/skc_daddr zeroed, so its traffic was silently
    // discarded by the zero-address filter rather than deliberately.
    __u8 saddr[IPV6_ADDR_LEN];
    __u8 daddr[IPV6_ADDR_LEN];
    if (!read_sock_addrs(sk, saddr, daddr))
        return 0;

    __u16 dport = bpf_ntohs(skc.skc_dport);

    // The socket only knows a peer if the application connect()ed. An
    // unconnected sendto() — how musl's resolver issues every DNS query
    // — carries its destination in the message header instead, and
    // taking it from the socket yielded 0.0.0.0:0, which the filter
    // below then dropped as unspecified. Must run BEFORE the
    // skip_v4_mapped test: that test asks what the destination is, and
    // until this point an unconnected v6 socket answers `::`.
    __u8 msg_daddr[IPV6_ADDR_LEN];
    __u16 msg_dport = 0;
    if (read_msghdr_dest(msg, msg_daddr, &msg_dport))
    {
        __builtin_memcpy(daddr, msg_daddr, IPV6_ADDR_LEN);
        dport = msg_dport;
    }

    // See the contract above: the v6 entry point leaves v4-mapped sends
    // to the v4 hook the kernel is about to invoke.
    if (skip_v4_mapped && addr_is_v4_mapped(daddr))
        return 0;

    // Apply common filtering helper. The udp_egress variant tolerates an
    // unspecified SOURCE, which is what a socket bound to INADDR_ANY has
    // at this point in the send — the route that picks one has not run
    // yet. See should_filter_udp_egress in helper.h.
    if (should_filter_udp_egress(saddr, daddr))
        return 0;

    // Check if this is a new connection (reduces duplicate events by 80-90%)
    // Uses 4-tuple to handle ephemeral source port rotation
    struct conn_key conn = {
        .inum = inum,
        .generation = generation,
        .dport = dport,
        .protocol = 2, // UDP
        .direction = 1, // Egress
    };
    __builtin_memcpy(conn.saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(conn.daddr, daddr, IPV6_ADDR_LEN);

    if (connection_already_seen(&conn))
        return 0; // Already published for this flow class

    // Reserve space in ring buffer
    struct network_event_data *event;
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0; // Buffer full: nothing marked yet, so the next packet retries

    // Fill event data
    event->inum = inum;
    __builtin_memcpy(event->saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(event->daddr, daddr, IPV6_ADDR_LEN);
    event->sport = skc.skc_num;
    event->dport = dport;
    event->kind = 3; // UDP
    event->_pad = 0; // ring-buffer memory is not zeroed on reserve

    // Submit to userspace
    bpf_ringbuf_submit(event, 0);
    mark_connection_seen(&conn);

    return 0;
}

// Use fentry instead of kprobe for better performance (lower overhead)
SEC("fentry/udp_sendmsg")
int BPF_PROG(trace_udp_send, struct sock *sk, struct msghdr *msg, size_t len)
{
    return handle_udp_send(sk, msg, /* skip_v4_mapped = */ false);
}

// Twin entry point for native IPv6 UDP. Without it, AF_INET6 UDP egress
// produced zero events and generated policies silently omitted DNS on
// IPv6-primary clusters. Autoload is turned off in bpf.rs when the
// running kernel has no udpv6_sendmsg (CONFIG_IPV6=n, or the ipv6
// module not loaded) so the controller still starts there.
SEC("fentry/udpv6_sendmsg")
int BPF_PROG(trace_udpv6_send, struct sock *sk, struct msghdr *msg, size_t len)
{
    return handle_udp_send(sk, msg, /* skip_v4_mapped = */ true);
}

// Hook into tcp_set_state to detect ESTABLISHED connections (outbound)
// This ensures we only record successful connections, not failed attempts
SEC("fentry/tcp_set_state")
int BPF_PROG(trace_tcp_state_change, struct sock *sk, int state)
{
    if (!sk)
        return 0;

    // Only record when a connection completes.
    if (state != TCP_ESTABLISHED)
        return 0;

    // Read socket common structure once (batch read) for the ports
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    // Resolve addresses; also acts as the family check that used to be
    // an explicit `skc_family != AF_INET` bail here (which is what made
    // IPv6 flows invisible).
    __u8 saddr[IPV6_ADDR_LEN];
    __u8 daddr[IPV6_ADDR_LEN];
    if (!read_sock_addrs(sk, saddr, daddr))
        return 0;

    // Get network namespace inode
    __u64 inum = 0;
    __u32 generation = 0;
    if (!get_and_validate_inum(sk, &inum, &generation))
        return 0;

    // Apply common filtering helper
    if (should_filter_traffic(saddr, daddr))
        return 0;

    __u16 sport = skc.skc_num;
    __u16 dport = bpf_ntohs(skc.skc_dport);

    // Direction comes from the socket's PRE-transition state, not a
    // port heuristic. At fentry, tcp_set_state's body has not run yet,
    // so skc_state (already in the batch-read copy above — it lives in
    // the config-independent first 24 bytes of sock_common) still
    // holds the OLD state. The kernel reaches ESTABLISHED from exactly
    // two states: SYN_SENT for an actively-opened socket (this pod is
    // the client — egress) and SYN_RECV for a passively-accepted one
    // (this pod is the server — ingress). Both values are pinned to
    // the BPF_TCP_* UAPI enum by BUILD_BUG_ONs inside tcp_set_state
    // itself, so a BPF program may rely on them.
    //
    // The heuristic this replaces — "local port > 1024 means egress" —
    // flipped every ACCEPTED connection on a high-port listener into
    // an egress flow toward the client's EPHEMERAL source port, one
    // recorded flow per client port: a kubelet-probed workload
    // accumulated 1,798 distinct "egress ports" (a 3,649-line
    // generated policy), and 96.6% of a production pod_traffic table
    // was this artifact.
    __u8 direction;
    if (skc.skc_state == TCP_SYN_SENT)
        direction = 1; // Egress: active open completing
    else if (skc.skc_state == TCP_SYN_RECV)
        direction = 2; // Ingress: passive open completing
    else
        return 0; // No other state legitimately becomes ESTABLISHED

    // Check if this is a new connection (reduces duplicate events).
    // Dedup on the STABLE port for the direction: the local listen
    // port for ingress, the remote service port for egress. Keying
    // ingress on the client's ephemeral port made every accepted
    // connection look new, defeating kernel-side dedup entirely.
    struct conn_key conn = {
        .inum = inum,
        .generation = generation,
        .dport = (direction == 2) ? sport : dport,
        .protocol = 1, // TCP
        .direction = direction,
    };
    __builtin_memcpy(conn.saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(conn.daddr, daddr, IPV6_ADDR_LEN);

    if (connection_already_seen(&conn))
        return 0; // Already published for this flow class

    // Reserve space in ring buffer
    struct network_event_data *tcp_event;
    tcp_event = bpf_ringbuf_reserve(&network_events, sizeof(*tcp_event), 0);
    if (!tcp_event)
        return 0; // Buffer full: nothing marked yet, so the next packet retries

    // Fill event data
    tcp_event->inum = inum;
    __builtin_memcpy(tcp_event->saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(tcp_event->daddr, daddr, IPV6_ADDR_LEN);
    tcp_event->sport = sport;
    tcp_event->dport = dport;
    tcp_event->kind = direction; // 1=Egress or 2=Ingress
    tcp_event->_pad = 0;

    // Submit to userspace
    bpf_ringbuf_submit(tcp_event, 0);
    mark_connection_seen(&conn);

    return 0;
}

SEC("kprobe/inet_csk_accept")
int BPF_KPROBE(tcp_accept_entry, struct sock *sk)
{
    // Early validation - only store context if socket is in tracked namespace
    __u64 inum = 0;
    __u32 generation = 0;
    if (!get_and_validate_inum(sk, &inum, &generation))
        return 0;

    // Store both listening socket and inum for kretprobe
    // Note: We store the listening socket's inum, the accepted socket comes from kretprobe
    struct tcp_connect_ctx ctx_data = {
        .sk = NULL, // Will use new_sk from kretprobe
        .inum = inum,
        .generation = generation,
    };

    __u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcp_ctx, &tid, &ctx_data, BPF_ANY);

    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(tcp_accept_exit, struct sock *new_sk)
{
    __u32 tid = bpf_get_current_pid_tgid();
    struct tcp_connect_ctx *ctx_data = bpf_map_lookup_elem(&tcp_ctx, &tid);

    // Always cleanup
    if (!ctx_data)
        return 0;

    __u64 inum = ctx_data->inum;
    __u32 generation = ctx_data->generation;
    bpf_map_delete_elem(&tcp_ctx, &tid);

    // Check for failed accept
    if (!new_sk)
        return 0;

    // Read socket common structure once (batch read) for the ports
    struct sock_common skc;
    BPF_CORE_READ_INTO(&skc, new_sk, __sk_common);

    // Resolve addresses and reject unsupported families. Like
    // udp_sendmsg, this path had no family check before IPv6 support.
    __u8 saddr[IPV6_ADDR_LEN];
    __u8 daddr[IPV6_ADDR_LEN];
    if (!read_sock_addrs(new_sk, saddr, daddr))
        return 0;

    // Apply common filtering helper
    if (should_filter_traffic(saddr, daddr))
        return 0;

    // Check if this is a new connection (reduces duplicate events).
    // Dedup on the LOCAL listen port — the stable side for ingress —
    // matching the key trace_tcp_state_change builds for the same
    // accepted socket, so the two ingress emitters collapse into one
    // event instead of each reporting per client ephemeral port.
    __u16 dport = __bpf_ntohs(skc.skc_dport);

    struct conn_key conn = {
        .inum = inum,
        .generation = generation,
        .dport = skc.skc_num,
        .protocol = 1, // TCP
        .direction = 2, // Ingress
    };
    __builtin_memcpy(conn.saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(conn.daddr, daddr, IPV6_ADDR_LEN);

    if (connection_already_seen(&conn))
        return 0; // Already published for this flow class

    // Reserve space in ring buffer
    struct network_event_data *accept_event;
    accept_event = bpf_ringbuf_reserve(&network_events, sizeof(*accept_event), 0);
    if (!accept_event)
        return 0; // Buffer full: nothing marked yet, so the next packet retries

    // Fill event data
    accept_event->inum = inum;
    __builtin_memcpy(accept_event->saddr, saddr, IPV6_ADDR_LEN);
    __builtin_memcpy(accept_event->daddr, daddr, IPV6_ADDR_LEN);
    accept_event->sport = skc.skc_num;
    accept_event->dport = dport;
    accept_event->kind = 2; // TCP Ingress
    accept_event->_pad = 0;

    // Submit to userspace
    bpf_ringbuf_submit(accept_event, 0);
    mark_connection_seen(&conn);

    return 0;
}

char _license[] SEC("license") = "GPL";
