-- Live compute gauge per container: the most recent sample the
-- controller shipped for it (docs/design/compute-contention-monitoring.md,
-- D5). One row per LIVE container, keyed on `container_uid`
-- (`<pod_uid>/<container>`) and UPSERTED on every sample interval, so the
-- table never exceeds the number of running containers regardless of
-- cadence — the property that keeps this from becoming another
-- pod_traffic-shaped incident. Rows whose `updated_at` goes stale (the
-- container died, the node's controller stopped) are pruned by
-- retention.rs after 10 minutes.
--
-- Every `cpu_*` / `mem_*` counter (usage, periods, throttle, events,
-- refault, pgmajfault) is a DELTA over `interval_ms`, not a cumulative
-- value; gauges (`mem_current`, `mem_working_set`, `*_psi_*`) are
-- instantaneous. `cpu_usage_millis` is derived at ingest
-- (usage_usec / interval_ms = millicores) so readers never redo the
-- arithmetic. Request / limit come from the pod spec, captured by the
-- controller at registration, so a gauge can be normalised without the
-- API server. The `runq_*` quantiles are NULL when the scheduler probe is
-- not loaded on that node; `blame` is the per-victim culprit list exactly
-- as it arrived on the wire (a JSONB array of {cgroup_id, kind, ref,
-- container_uid, count, wait_ns}).
CREATE TABLE IF NOT EXISTS pod_compute_latest (
    container_uid       TEXT PRIMARY KEY,
    pod_uid             TEXT NOT NULL,
    namespace           TEXT NOT NULL,
    pod_name            TEXT NOT NULL,
    container           TEXT NOT NULL,
    node                TEXT NOT NULL,
    cgroup_id           BIGINT NOT NULL,
    ts                  TIMESTAMP NOT NULL,
    interval_ms         INTEGER NOT NULL,
    cpu_usage_millis    DOUBLE PRECISION NOT NULL,
    cpu_quota_usec      BIGINT,
    cpu_period_usec     BIGINT NOT NULL,
    cpu_request_millis  BIGINT,
    cpu_limit_millis    BIGINT,
    cpu_nr_periods      BIGINT NOT NULL,
    cpu_nr_throttled    BIGINT NOT NULL,
    cpu_throttled_usec  BIGINT NOT NULL,
    cpu_psi_some10      DOUBLE PRECISION NOT NULL,
    cpu_psi_full10      DOUBLE PRECISION NOT NULL,
    mem_current         BIGINT NOT NULL,
    mem_working_set     BIGINT NOT NULL,
    mem_limit           BIGINT,
    mem_request         BIGINT,
    mem_psi_some10      DOUBLE PRECISION NOT NULL,
    mem_psi_full10      DOUBLE PRECISION NOT NULL,
    mem_events_high     BIGINT NOT NULL,
    mem_events_max      BIGINT NOT NULL,
    mem_oom_kill        BIGINT NOT NULL,
    mem_refault         BIGINT NOT NULL,
    mem_pgmajfault      BIGINT NOT NULL,
    runq_count          BIGINT,
    runq_p50_us         BIGINT,
    runq_p95_us         BIGINT,
    runq_p99_us         BIGINT,
    runq_max_us         BIGINT,
    runq_overflow       BIGINT,
    blame               JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at          TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

-- `GET /compute/latest?namespace=` is the 5 s frontend poll; it must be
-- an index range scan, not a table scan, on a cluster with thousands of
-- containers. The node index serves the "nodes hosting these containers"
-- join and the per-node views.
CREATE INDEX IF NOT EXISTS idx_pod_compute_latest_namespace ON pod_compute_latest (namespace);
CREATE INDEX IF NOT EXISTS idx_pod_compute_latest_node ON pod_compute_latest (node);
-- Dead-container prune (retention.rs) selects by updated_at.
CREATE INDEX IF NOT EXISTS idx_pod_compute_latest_updated_at ON pod_compute_latest (updated_at);
