-- Cumulative BPF map insert failures since the scheduler probe loaded
-- (design D4: "a leak shows up as a number, not as a phantom p99" — and
-- so does loss). A failed `runq_hist` update means a victim's latency
-- sample was dropped; a failed `pair` update means a blame sample was.
-- Either climbing under load says the maps are undersized and the
-- histogram / blame numbers are under-counts. Nullable: an older
-- controller sends neither. Added LAST (positional Queryable).
ALTER TABLE node_compute_latest ADD COLUMN IF NOT EXISTS bpf_hist_update_failures BIGINT;
ALTER TABLE node_compute_latest ADD COLUMN IF NOT EXISTS bpf_pair_update_failures BIGINT;
