-- Static node facts a compute gauge needs (design D10): the numbers a
-- container's usage is normalised against when it has neither a limit
-- nor a request (`cpu_cores`, `memory_bytes`), and the three facts that
-- decide whether the feature can work on the node at all — kernel
-- version, cgroup version (1 or 2; per-cgroup PSI only exists on v2) and
-- whether PSI is compiled in. Node facts are reported once at controller
-- start, before any BPF program loads, so only STATIC values belong here;
-- anything that depends on configuration or a load result is live and
-- goes into node_compute_latest instead.
--
-- All nullable with no default, for the same reason as
-- policy_enforcement: NULL is "a controller that predates this column",
-- which is a different state from a controller that looked. Added last
-- so the physical column order matches the positional Queryable on
-- NodeFact.
ALTER TABLE node_facts ADD COLUMN IF NOT EXISTS cpu_cores INTEGER;
ALTER TABLE node_facts ADD COLUMN IF NOT EXISTS memory_bytes BIGINT;
ALTER TABLE node_facts ADD COLUMN IF NOT EXISTS kernel_version TEXT;
ALTER TABLE node_facts ADD COLUMN IF NOT EXISTS cgroup_version SMALLINT;
ALTER TABLE node_facts ADD COLUMN IF NOT EXISTS psi_available BOOLEAN;
