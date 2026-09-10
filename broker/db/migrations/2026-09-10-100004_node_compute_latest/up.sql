-- One row per node: the live half of the compute feature's node state
-- (design D10). node_facts carries what is static and reported once at
-- controller start; everything that depends on configuration or on a
-- load result travels with every sample and lands here, upserted on
-- `node`: whether the feature is on (`compute_enabled`), whether the node
-- can support it at all (`compute_supported` = cgroup v2 AND PSI), and
-- whether the scheduler probe attached (`contention_loaded`). The UI
-- reads this row to say WHY a node's pods have no gauge, instead of
-- drawing an empty bar. A node with no row at all is "feature off, or a
-- controller older than this feature".
--
-- The rest is the per-node evidence the findings engine and the overhead
-- estimate need: /proc/pressure/{cpu,memory} some/full avg10, the node's
-- context-switch rate (what the probe's per-switch cost multiplies), BPF
-- map occupancy (a leak shows up as a number here, not as a phantom p99)
-- and the share of blame the controller could not attribute
-- (`unknown_blame_share`; if it climbs, attribution is broken and the UI
-- says so rather than blaming "unknown"). Stale rows are left in place —
-- the table is node-count sized and `updated_at` tells a reader how old
-- the row is.
CREATE TABLE IF NOT EXISTS node_compute_latest (
    node                TEXT PRIMARY KEY,
    ts                  TIMESTAMP NOT NULL,
    interval_ms         INTEGER NOT NULL,
    ctxt_per_sec        DOUBLE PRECISION NOT NULL,
    compute_enabled     BOOLEAN NOT NULL,
    compute_supported   BOOLEAN NOT NULL,
    contention_loaded   BOOLEAN NOT NULL,
    cpu_some10          DOUBLE PRECISION NOT NULL,
    cpu_full10          DOUBLE PRECISION NOT NULL,
    mem_some10          DOUBLE PRECISION NOT NULL,
    mem_full10          DOUBLE PRECISION NOT NULL,
    cpu_cores           INTEGER NOT NULL,
    memory_bytes        BIGINT NOT NULL,
    bpf_runq_enqueued   BIGINT NOT NULL,
    bpf_runq_hist       BIGINT NOT NULL,
    bpf_pair            BIGINT NOT NULL,
    unknown_blame_share DOUBLE PRECISION NOT NULL,
    updated_at          TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);
