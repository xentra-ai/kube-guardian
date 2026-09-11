-- Per-container compute history at minute (and, after downsampling,
-- five-minute) resolution (design D5). The controller folds its samples
-- into one row per container per minute and POSTs them; the broker only
-- inserts. Gauges carry avg / max / last over the row's window, counters
-- are the window's sum, `runq_hist` is the summed 24-bucket run-queue
-- latency histogram (bucket b = [2^b, 2^(b+1)) µs, bucket 23 = overflow)
-- so a quantile can be re-derived over any longer window by adding
-- buckets. `resolution_secs` says which tier a row belongs to: 60 for a
-- controller-written minute row, 300 for a row retention.rs produced by
-- folding five of them. Both tiers live in one table so the history
-- endpoint returns whatever resolution the requested window has.
--
-- Row budget is the risk here (3 000 containers x 1 440 min/day = 4.3 M
-- rows/day), so this table is bounded by retention.rs: minute rows older
-- than COMPUTE_HISTORY_MINUTE_HOURS are downsampled, and everything older
-- than COMPUTE_HISTORY_RETENTION_DAYS is pruned in batches. The (ts) index
-- is what makes those passes range scans; the other two serve the reads.
CREATE TABLE IF NOT EXISTS pod_compute_history (
    id                      BIGSERIAL PRIMARY KEY,
    container_uid           TEXT NOT NULL,
    pod_uid                 TEXT NOT NULL,
    namespace               TEXT NOT NULL,
    pod_name                TEXT NOT NULL,
    container               TEXT NOT NULL,
    node                    TEXT NOT NULL,
    ts                      TIMESTAMP NOT NULL,
    resolution_secs         INTEGER NOT NULL,
    cpu_usage_millis_avg    DOUBLE PRECISION NOT NULL,
    cpu_usage_millis_max    DOUBLE PRECISION NOT NULL,
    cpu_usage_millis_last   DOUBLE PRECISION NOT NULL,
    cpu_quota_usec          BIGINT,
    cpu_period_usec         BIGINT NOT NULL,
    cpu_request_millis      BIGINT,
    cpu_limit_millis        BIGINT,
    cpu_nr_periods          BIGINT NOT NULL,
    cpu_nr_throttled        BIGINT NOT NULL,
    cpu_throttled_usec      BIGINT NOT NULL,
    cpu_psi_some10_avg      DOUBLE PRECISION NOT NULL,
    cpu_psi_some10_max      DOUBLE PRECISION NOT NULL,
    cpu_psi_full10_avg      DOUBLE PRECISION NOT NULL,
    cpu_psi_full10_max      DOUBLE PRECISION NOT NULL,
    mem_current_avg         BIGINT NOT NULL,
    mem_current_max         BIGINT NOT NULL,
    mem_current_last        BIGINT NOT NULL,
    mem_working_set_avg     BIGINT NOT NULL,
    mem_working_set_max     BIGINT NOT NULL,
    mem_working_set_last    BIGINT NOT NULL,
    mem_limit               BIGINT,
    mem_request             BIGINT,
    mem_psi_some10_avg      DOUBLE PRECISION NOT NULL,
    mem_psi_some10_max      DOUBLE PRECISION NOT NULL,
    mem_psi_full10_avg      DOUBLE PRECISION NOT NULL,
    mem_psi_full10_max      DOUBLE PRECISION NOT NULL,
    mem_events_high         BIGINT NOT NULL,
    mem_events_max          BIGINT NOT NULL,
    mem_oom_kill            BIGINT NOT NULL,
    mem_refault             BIGINT NOT NULL,
    mem_pgmajfault          BIGINT NOT NULL,
    runq_count              BIGINT,
    runq_p50_us             BIGINT,
    runq_p95_us             BIGINT,
    runq_p99_us             BIGINT,
    runq_max_us             BIGINT,
    runq_overflow           BIGINT,
    runq_hist               BIGINT[]
);

CREATE INDEX IF NOT EXISTS idx_pod_compute_history_pod_ts ON pod_compute_history (pod_uid, ts DESC);
CREATE INDEX IF NOT EXISTS idx_pod_compute_history_node_ts ON pod_compute_history (node, ts DESC);
CREATE INDEX IF NOT EXISTS idx_pod_compute_history_ts ON pod_compute_history (ts);
