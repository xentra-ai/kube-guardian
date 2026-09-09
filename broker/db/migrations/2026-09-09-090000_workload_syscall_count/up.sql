-- Number of distinct syscalls in `syscalls`, stored at write time.
--
-- `GET /seccomp/profiles` returns one summary per workload and the only
-- thing it derives from the syscall set is its cardinality. It was
-- getting that by selecting the whole `syscalls` TEXT blob for every
-- workload and splitting it in Rust: on the dev cluster, 1696 blobs
-- carrying 113,995 syscall names, allocated and dropped on every 15s UI
-- poll, to produce 1696 integers.
--
-- That is the allocation behind the broker OOMKill in #1514. Counting in
-- the read path was the wrong place for it: the number cannot change
-- without `syscalls` changing, and `recompute_workload` already holds
-- the count when it writes the blob (it logs it). Storing it there makes
-- the list path a plain column read and lets the blob stay in the
-- database, where it is only needed by the handful of workloads with a
-- mirrored SeccompProfile CR that require drift detection.
ALTER TABLE workload_syscalls ADD COLUMN IF NOT EXISTS syscall_count INTEGER;

-- Backfill, so the fix takes effect on deploy rather than whenever each
-- workload next happens to change.
--
-- Without this every existing row has NULL and the read path falls back
-- to fetching its blob to count it, which is the exact behaviour this
-- change exists to remove. `recompute_workload` only fires when a
-- workload's syscalls change, so a stable workload could sit on NULL
-- indefinitely and the endpoint would keep reading every blob.
--
-- Safe to do inline here, unlike the `pod_traffic` migrations that
-- deliberately avoid touching existing rows: `workload_syscalls` is keyed
-- by (namespace, kind, name), so it is bounded by distinct workloads
-- (1696 on the dev cluster) rather than by telemetry accumulation
-- (millions). One UPDATE over a few thousand rows is not the same
-- operation as one over a 6.7M-row table.
--
-- The expression mirrors `split_set` in seccomp.rs: split on commas, trim,
-- drop empties, count distinct.
--
-- `regexp_replace(tok, '^\s+|\s+$', '', 'g')` rather than `btrim`, because
-- `btrim` strips only the ASCII whitespace you name while Rust's `str::trim`
-- also strips Unicode whitespace. A blob token like "write,<NBSP>write" would
-- count 2 here and 1 in Rust. Under a UTF-8 locale `\s` covers the Unicode
-- set, which closes that gap rather than documenting it.
--
-- The gap was worth closing rather than tolerating: `valid_syscall_name` gates
-- only the export path, not `recompute_workload`, so nothing structurally
-- prevents such a token. It is prevented by the controller emitting clean
-- names, which is a behaviour rather than an invariant.
--
-- Note the NULL fallback in the read path does NOT cover a disagreement here.
-- A divergent row gets a wrong non-NULL value, and a non-NULL value is exactly
-- what suppresses the fallback. What does bound it is self-healing:
-- `recompute_workload` writes the blob and the Rust-derived count together, so
-- the stored value becomes correct the next time that workload's syscalls
-- change. The NULL fallback covers rows this UPDATE skips, which is a
-- different case.
UPDATE workload_syscalls
SET syscall_count = (
    SELECT count(DISTINCT regexp_replace(tok, '^\s+|\s+$', '', 'g'))
    FROM unnest(string_to_array(syscalls, ',')) AS tok
    WHERE regexp_replace(tok, '^\s+|\s+$', '', 'g') <> ''
)
WHERE syscall_count IS NULL;
