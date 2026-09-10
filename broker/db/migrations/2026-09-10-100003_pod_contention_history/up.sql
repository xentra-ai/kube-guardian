-- Who was on the CPU while a tracked container waited (design D4/D6).
-- One row per (victim container, culprit cgroup) per minute, carrying the
-- scheduler-probe pair counters summed over that minute: how many times
-- the culprit was the task switched in ahead of the victim (`count`) and
-- the run-queue latency the victim accumulated behind it (`wait_ns`). The
-- controller ships only the top pairs per victim (10 by wait_ns), so this
-- is bounded by victims x 10 per minute, not by pair cardinality.
--
-- `culprit_kind` is `pod` (a tracked or untracked container; `culprit_ref`
-- is `ns/pod/container` or `pod:<uid8>`), `system` (a systemd unit, e.g.
-- kubelet), `kernel` (pid 0 / cgroup 0) or `unknown` (attribution failed;
-- the findings engine never names an unknown as a culprit and reports an
-- unknown-dominated node instead of guessing). `culprit_container_uid` is
-- set only for tracked pod culprits, and is what joins a culprit back to
-- its own usage row so D6's "using more than its request" test can run.
--
-- Same retention as pod_compute_history: pruned by retention.rs after
-- COMPUTE_HISTORY_RETENTION_DAYS (there is no downsample; pairs are
-- summed by the reader over whatever window it asks for).
CREATE TABLE IF NOT EXISTS pod_contention_history (
    id                      BIGSERIAL PRIMARY KEY,
    ts                      TIMESTAMP NOT NULL,
    node                    TEXT NOT NULL,
    victim_container_uid    TEXT NOT NULL,
    victim_pod_uid          TEXT NOT NULL,
    victim_namespace        TEXT NOT NULL,
    culprit_cgroup_id       BIGINT NOT NULL,
    culprit_kind            TEXT NOT NULL,
    culprit_ref             TEXT NOT NULL,
    culprit_container_uid   TEXT,
    count                   BIGINT NOT NULL,
    wait_ns                 BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pod_contention_history_victim_ts ON pod_contention_history (victim_container_uid, ts DESC);
CREATE INDEX IF NOT EXISTS idx_pod_contention_history_node_ts ON pod_contention_history (node, ts DESC);
CREATE INDEX IF NOT EXISTS idx_pod_contention_history_ts ON pod_contention_history (ts);
