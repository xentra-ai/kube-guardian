//! Startup configuration for the compute sampler and the scheduler
//! contention probe, from the `COMPUTE_*` environment the chart renders.
//!
//! Same shape as `capture_tiers::CaptureConfig`: a pure `from_values`
//! over the raw strings, unit-tested, and a thin `from_env` on top.
//! Every value has a default, and an unparseable one warns and falls
//! back rather than refusing to start — the gauges are a default-on
//! feature and must never take capture down.

use std::path::PathBuf;
use std::time::Duration;
use tracing::warn;

use crate::pod_watcher::parse_lenient_bool;

pub const DEFAULT_SAMPLE_INTERVAL_SECS: u64 = 5;
pub const DEFAULT_MIN_RUNQ_LATENCY_US: u64 = 100;
pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
pub const DEFAULT_HOST_PROC: &str = "/proc";

/// Pod annotation that opts a workload out of sampling and tracking.
pub const COMPUTE_ANNOTATION: &str = "kguardian.dev/compute";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeConfig {
    /// Master switch (`COMPUTE_ENABLED`). Off means nothing is spawned,
    /// nothing is registered and no envelope is ever posted.
    pub enabled: bool,
    /// `COMPUTE_SAMPLE_INTERVAL_SECS`, clamped to at least 1 s.
    pub sample_interval: Duration,
    /// `COMPUTE_CONTENTION_ENABLED`: load the `sched_contention` probe.
    pub contention_enabled: bool,
    /// `COMPUTE_MIN_RUNQ_LATENCY_US`: in-kernel filter for the probe.
    pub min_runq_latency_us: u64,
    /// `COMPUTE_CGROUP_ROOT`: where the host's cgroup v2 root is mounted.
    pub cgroup_root: PathBuf,
    /// `COMPUTE_HOST_PROC`: where the host's `/proc` is mounted.
    pub host_proc: PathBuf,
}

impl Default for ComputeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_interval: Duration::from_secs(DEFAULT_SAMPLE_INTERVAL_SECS),
            contention_enabled: false,
            min_runq_latency_us: DEFAULT_MIN_RUNQ_LATENCY_US,
            cgroup_root: PathBuf::from(DEFAULT_CGROUP_ROOT),
            host_proc: PathBuf::from(DEFAULT_HOST_PROC),
        }
    }
}

fn parse_u64(name: &str, raw: Option<&str>, default: u64) -> u64 {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => default,
        Some(s) => match s.parse::<u64>() {
            Ok(v) => v,
            Err(_) => {
                warn!(
                    env = name,
                    value = s,
                    default,
                    "not an unsigned integer; using default"
                );
                default
            }
        },
    }
}

fn parse_path(raw: Option<&str>, default: &str) -> PathBuf {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => PathBuf::from(s),
        None => PathBuf::from(default),
    }
}

impl ComputeConfig {
    /// Pure parser over the raw env values, in the order of the
    /// contract's table.
    pub fn from_values(
        enabled: Option<&str>,
        sample_interval_secs: Option<&str>,
        contention_enabled: Option<&str>,
        min_runq_latency_us: Option<&str>,
        cgroup_root: Option<&str>,
        host_proc: Option<&str>,
    ) -> Self {
        let mut secs = parse_u64(
            "COMPUTE_SAMPLE_INTERVAL_SECS",
            sample_interval_secs,
            DEFAULT_SAMPLE_INTERVAL_SECS,
        );
        if secs == 0 {
            warn!("COMPUTE_SAMPLE_INTERVAL_SECS=0 is not a cadence; using 1s");
            secs = 1;
        }
        Self {
            enabled: parse_lenient_bool(enabled.unwrap_or_default(), true),
            sample_interval: Duration::from_secs(secs),
            contention_enabled: parse_lenient_bool(contention_enabled.unwrap_or_default(), false),
            min_runq_latency_us: parse_u64(
                "COMPUTE_MIN_RUNQ_LATENCY_US",
                min_runq_latency_us,
                DEFAULT_MIN_RUNQ_LATENCY_US,
            ),
            cgroup_root: parse_path(cgroup_root, DEFAULT_CGROUP_ROOT),
            host_proc: parse_path(host_proc, DEFAULT_HOST_PROC),
        }
    }

    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok();
        Self::from_values(
            get("COMPUTE_ENABLED").as_deref(),
            get("COMPUTE_SAMPLE_INTERVAL_SECS").as_deref(),
            get("COMPUTE_CONTENTION_ENABLED").as_deref(),
            get("COMPUTE_MIN_RUNQ_LATENCY_US").as_deref(),
            get("COMPUTE_CGROUP_ROOT").as_deref(),
            get("COMPUTE_HOST_PROC").as_deref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_nothing_is_set() {
        let c = ComputeConfig::from_values(None, None, None, None, None, None);
        assert_eq!(c, ComputeConfig::default());
        assert!(c.enabled);
        assert!(!c.contention_enabled);
        assert_eq!(c.sample_interval, Duration::from_secs(5));
        assert_eq!(c.min_runq_latency_us, 100);
        assert_eq!(c.cgroup_root, PathBuf::from("/sys/fs/cgroup"));
        assert_eq!(c.host_proc, PathBuf::from("/proc"));
    }

    #[test]
    fn every_value_is_read() {
        let c = ComputeConfig::from_values(
            Some("False"),
            Some(" 10 "),
            Some("TRUE"),
            Some("250"),
            Some("/host/sys/fs/cgroup"),
            Some("/host/proc\n"),
        );
        assert!(!c.enabled);
        assert_eq!(c.sample_interval, Duration::from_secs(10));
        assert!(c.contention_enabled);
        assert_eq!(c.min_runq_latency_us, 250);
        assert_eq!(c.cgroup_root, PathBuf::from("/host/sys/fs/cgroup"));
        assert_eq!(c.host_proc, PathBuf::from("/host/proc"));
    }

    #[test]
    fn garbage_falls_back_to_defaults_and_zero_interval_is_clamped() {
        let c = ComputeConfig::from_values(
            Some("maybe"),
            Some("fast"),
            Some("nope"),
            Some("-1"),
            Some("  "),
            Some(""),
        );
        assert!(c.enabled, "unknown bool keeps the default (on)");
        assert_eq!(c.sample_interval, Duration::from_secs(5));
        assert!(!c.contention_enabled);
        assert_eq!(c.min_runq_latency_us, 100);
        assert_eq!(c.cgroup_root, PathBuf::from("/sys/fs/cgroup"));
        let z = ComputeConfig::from_values(None, Some("0"), None, None, None, None);
        assert_eq!(z.sample_interval, Duration::from_secs(1));
    }
}
