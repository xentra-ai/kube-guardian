ALTER TABLE node_facts DROP COLUMN IF EXISTS psi_available;
ALTER TABLE node_facts DROP COLUMN IF EXISTS cgroup_version;
ALTER TABLE node_facts DROP COLUMN IF EXISTS kernel_version;
ALTER TABLE node_facts DROP COLUMN IF EXISTS memory_bytes;
ALTER TABLE node_facts DROP COLUMN IF EXISTS cpu_cores;
