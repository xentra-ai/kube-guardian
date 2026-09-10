//! Per-container compute identity: the cgroup id registry behind the
//! compute sampler and the scheduler-contention probe.
//!
//! The netns `ContainerMap` (models.rs) is per pod and keyed by the
//! network-namespace inode; that is the right key for traffic and
//! syscalls and the wrong one for CPU accounting, where the scheduler
//! thinks in tasks and cgroups and limits are per container. This is the
//! parallel, per-container registry described in the design (D1): one
//! [`ContainerCompute`] per container, keyed by the 64-bit cgroup id that
//! `bpf_get_current_cgroup_id()` yields in BPF and `name_to_handle_at`
//! yields in userspace, plus one [`PodCompute`] per pod for the
//! pod-level rollup cgroup.
//!
//! Locking: a single `std::sync::RwLock` around a plain map, taken only
//! for synchronous, allocation-light operations. Every read returns an
//! owned `Arc` or a `Vec` snapshot, so no guard can outlive the call and
//! nothing here can be held across an `.await` — the hazard `clippy.toml`
//! guards the DashMap-based `ContainerMap` against does not arise.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

/// Requests and limits per container, captured from the pod spec at
/// registration so the broker never needs the API server to normalise a
/// gauge. `None` means unset in the spec.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceSpec {
    pub cpu_request_millis: Option<u64>,
    pub cpu_limit_millis: Option<u64>,
    pub memory_request_bytes: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
}

/// One container's compute identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerCompute {
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub container_name: String,
    pub container_id: String,
    pub pid: u32,
    /// Relative to the cgroup root, no leading slash.
    pub cgroup_path: String,
    pub cgroup_id: u64,
    pub resources: ResourceSpec,
    pub node: String,
}

impl ContainerCompute {
    /// `<pod_uid>/<container_name>` — the broker's primary key.
    pub fn container_uid(&self) -> String {
        format!("{}/{}", self.pod_uid, self.container_name)
    }
}

/// A pod's own cgroup (the parent of its container scopes), recorded so
/// pause-container and init-container time is not lost and so the graph
/// node can show a single gauge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodCompute {
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub pod_cgroup_path: String,
    pub pod_cgroup_id: u64,
}

/// Registration events for the BPF `tracked_cgroups` map. Only container
/// cgroups are announced: tasks live in the leaf scopes, and the pod
/// slice above them holds none of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeRegistration {
    Added { cgroup_id: u64 },
    Removed { cgroup_id: u64 },
}

#[derive(Default)]
struct Inner {
    containers: HashMap<u64, Arc<ContainerCompute>>,
    pods: HashMap<String, Arc<PodCompute>>,
    /// pod_uid -> container cgroup ids, for `remove_pod`.
    by_pod: HashMap<String, Vec<u64>>,
}

/// Registry of every container and pod cgroup this node samples.
pub struct ComputeRegistry {
    inner: RwLock<Inner>,
    events: broadcast::Sender<ComputeRegistration>,
}

pub type ComputeMap = Arc<ComputeRegistry>;

/// Capacity of the registration channel. A receiver that falls further
/// behind than this sees `Lagged` and must resync from `containers()`;
/// the sampler does exactly that.
const EVENT_CAPACITY: usize = 4096;

impl Default for ComputeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ComputeRegistry {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self {
            inner: RwLock::new(Inner::default()),
            events,
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Insert (or replace) a container, keyed by cgroup id. Idempotent:
    /// re-registering the same cgroup id emits no event, so the 60 s pod
    /// resync does not churn the BPF map. A container whose cgroup id
    /// changed (restart → new scope) is announced as a fresh `Added`,
    /// and its previous id is retired with `Removed`.
    pub fn insert_container(&self, c: ContainerCompute) {
        let mut events = Vec::new();
        {
            let mut g = self.write();
            // Retire a stale id for the same container name (restart).
            let stale: Vec<u64> = g
                .by_pod
                .get(&c.pod_uid)
                .map(|ids| {
                    ids.iter()
                        .copied()
                        .filter(|id| {
                            *id != c.cgroup_id
                                && g.containers
                                    .get(id)
                                    .is_some_and(|old| old.container_name == c.container_name)
                        })
                        .collect()
                })
                .unwrap_or_default();
            for id in &stale {
                g.containers.remove(id);
                events.push(ComputeRegistration::Removed { cgroup_id: *id });
            }
            let ids = g.by_pod.entry(c.pod_uid.clone()).or_default();
            ids.retain(|x| !stale.contains(x));
            let is_new = !ids.contains(&c.cgroup_id);
            if is_new {
                ids.push(c.cgroup_id);
                events.push(ComputeRegistration::Added {
                    cgroup_id: c.cgroup_id,
                });
            }
            g.containers.insert(c.cgroup_id, Arc::new(c));
        }
        for e in events {
            let _ = self.events.send(e);
        }
    }

    pub fn insert_pod(&self, p: PodCompute) {
        self.write().pods.insert(p.pod_uid.clone(), Arc::new(p));
    }

    /// Remove a pod and every container registered under it.
    pub fn remove_pod(&self, pod_uid: &str) {
        let removed: Vec<u64> = {
            let mut g = self.write();
            g.pods.remove(pod_uid);
            let ids = g.by_pod.remove(pod_uid).unwrap_or_default();
            for id in &ids {
                g.containers.remove(id);
            }
            ids
        };
        for id in removed {
            let _ = self
                .events
                .send(ComputeRegistration::Removed { cgroup_id: id });
        }
    }

    /// Snapshot of every container; no guard is held on return.
    pub fn containers(&self) -> Vec<Arc<ContainerCompute>> {
        self.read().containers.values().map(Arc::clone).collect()
    }

    /// Snapshot of every pod-level cgroup.
    pub fn pods(&self) -> Vec<Arc<PodCompute>> {
        self.read().pods.values().map(Arc::clone).collect()
    }

    /// Every registered pod uid — used by the resync pass to retire pods
    /// that are gone from the API server without a watch event.
    pub fn pod_uids(&self) -> Vec<String> {
        let g = self.read();
        let mut uids: Vec<String> = g.by_pod.keys().cloned().collect();
        for uid in g.pods.keys() {
            if !uids.contains(uid) {
                uids.push(uid.clone());
            }
        }
        uids
    }

    pub fn lookup_cgroup(&self, cgroup_id: u64) -> Option<Arc<ContainerCompute>> {
        self.read().containers.get(&cgroup_id).map(Arc::clone)
    }

    /// The registered entry for a container by pod uid and name, so the
    /// pod watcher can skip the containerd lookup for a container it has
    /// already resolved.
    pub fn container_for(
        &self,
        pod_uid: &str,
        container_name: &str,
    ) -> Option<Arc<ContainerCompute>> {
        let g = self.read();
        g.by_pod.get(pod_uid)?.iter().find_map(|id| {
            g.containers
                .get(id)
                .filter(|c| c.container_name == container_name)
                .map(Arc::clone)
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ComputeRegistration> {
        self.events.subscribe()
    }
}

/// Resolve the 64-bit cgroup id of `<root>/<rel_path>` with
/// `name_to_handle_at(2)`.
///
/// On cgroup v2 the file handle kernfs hands back is the node's 64-bit
/// id (`FILEID_KERNFS`, 8 bytes, native endian — little-endian on every
/// architecture this controller builds for), which is the same value
/// `bpf_get_current_cgroup_id()` returns in BPF and `bpftool cgroup
/// tree` prints. bpftrace's `cgroupid()` and systemd read it the same
/// way.
pub fn cgroup_id_for_path(root: &Path, rel_path: &str) -> io::Result<u64> {
    let full = root.join(rel_path.trim_start_matches('/'));
    cgroup_id_for_full_path(&full)
}

/// Same as [`cgroup_id_for_path`] for an absolute path.
pub fn cgroup_id_for_full_path(full: &Path) -> io::Result<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(full.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;

    // struct file_handle { u32 handle_bytes; i32 handle_type; u8 f_handle[]; }
    // 8 bytes of header + up to MAX_HANDLE_SZ (128) of payload. The
    // kernfs handle is 8 bytes; over-allocating costs nothing and
    // avoids the EOVERFLOW round trip. Backed by `u64`s so the buffer
    // is at least as aligned as `file_handle` (4) and as the id (8).
    const MAX_HANDLE_SZ: usize = 128;
    let mut words = [0u64; (8 + MAX_HANDLE_SZ) / 8];
    // SAFETY: the buffer is at least the size of the header plus the
    // advertised payload and is 8-byte aligned; `handle_bytes` is
    // written before the call so the kernel knows how much payload
    // space follows, and the kernel writes at most that many bytes
    // after the 8-byte header.
    let rc = unsafe {
        let handle = words.as_mut_ptr() as *mut libc::file_handle;
        (*handle).handle_bytes = MAX_HANDLE_SZ as u32;
        let mut mount_id: libc::c_int = 0;
        libc::name_to_handle_at(libc::AT_FDCWD, c_path.as_ptr(), handle, &mut mount_id, 0)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `words` is a plain-old-data array; viewing it as bytes is
    // always valid.
    let buf: &[u8] = unsafe {
        std::slice::from_raw_parts(words.as_ptr() as *const u8, std::mem::size_of_val(&words))
    };
    let handle_bytes = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if handle_bytes < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file handle is {handle_bytes} bytes, expected at least 8"),
        ));
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&buf[8..16]);
    Ok(u64::from_le_bytes(id))
}

/// The cgroup v2 path of `pid`, relative to the cgroup root with no
/// leading slash, from the `0::/...` line of `<host_proc>/<pid>/cgroup`.
pub fn cgroup_path_for_pid(host_proc: &Path, pid: u32) -> io::Result<String> {
    let raw = std::fs::read_to_string(host_proc.join(pid.to_string()).join("cgroup"))?;
    parse_proc_cgroup_v2(&raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no cgroup v2 (0::) entry for pid {pid}"),
        )
    })
}

/// Pure half of [`cgroup_path_for_pid`]: pick the unified-hierarchy line
/// out of a `/proc/<pid>/cgroup` body. On a hybrid (v1 + v2) host the
/// file has one line per v1 controller and a single `0::` line; on pure
/// v2 it is the only line.
pub fn parse_proc_cgroup_v2(body: &str) -> Option<String> {
    body.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| p.trim().trim_start_matches('/').to_string())
}

/// Parent of a container scope: the pod-level cgroup. Works for both
/// the systemd driver (`…/kubepods-burstable-pod<uid>.slice/cri-containerd-<cid>.scope`)
/// and cgroupfs (`kubepods/burstable/pod<uid>/<cid>`). `None` when the
/// path has no parent (a root-level cgroup).
pub fn pod_cgroup_path(container_cgroup_path: &str) -> Option<String> {
    let trimmed = container_cgroup_path.trim_matches('/');
    let idx = trimmed.rfind('/')?;
    Some(trimmed[..idx].to_string())
}

/// Parse a Kubernetes CPU quantity into millicores: `100m` → 100,
/// `1` → 1000, `2.5` → 2500, `0.5` → 500. Rejects anything else.
pub fn parse_cpu_millis(q: &str) -> Option<u64> {
    let q = q.trim();
    if q.is_empty() {
        return None;
    }
    if let Some(m) = q.strip_suffix('m') {
        return m.parse::<u64>().ok();
    }
    // Whole or decimal cores.
    let (int_part, frac_part) = match q.split_once('.') {
        Some((i, f)) => (i, f),
        None => (q, ""),
    };
    if !int_part.chars().all(|c| c.is_ascii_digit()) || int_part.is_empty() && frac_part.is_empty()
    {
        return None;
    }
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let whole: u64 = if int_part.is_empty() {
        0
    } else {
        int_part.parse().ok()?
    };
    // Up to three fractional digits are exact in millis; beyond that we
    // truncate, which is what the kubelet does when it rounds up to a
    // millicore for scheduling anyway.
    let mut millis = 0u64;
    let mut scale = 100u64;
    for c in frac_part.chars().take(3) {
        millis += u64::from(c.to_digit(10).unwrap_or(0)) * scale;
        scale /= 10;
    }
    whole.checked_mul(1000)?.checked_add(millis)
}

/// Parse a Kubernetes memory quantity into bytes: binary suffixes
/// (`Ki`/`Mi`/`Gi`/`Ti`/`Pi`/`Ei`), decimal suffixes (`k`/`M`/`G`/`T`/`P`/`E`),
/// exponent form (`1e6`) and plain integers. Decimal mantissas are
/// accepted (`1.5Gi`). Rejects anything else.
pub fn parse_memory_bytes(q: &str) -> Option<u64> {
    let q = q.trim();
    if q.is_empty() {
        return None;
    }
    let split = q
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(q.len());
    let (num, suffix) = q.split_at(split);
    if num.is_empty() {
        return None;
    }
    let multiplier: f64 = match suffix {
        "" => 1.0,
        "Ki" => 1024.0,
        "Mi" => 1024.0 * 1024.0,
        "Gi" => 1024.0 * 1024.0 * 1024.0,
        "Ti" => 1024.0_f64.powi(4),
        "Pi" => 1024.0_f64.powi(5),
        "Ei" => 1024.0_f64.powi(6),
        "k" => 1e3,
        "M" => 1e6,
        "G" => 1e9,
        "T" => 1e12,
        "P" => 1e15,
        "E" => 1e18,
        "m" => 1e-3, // milli-bytes exist in the API; round down below.
        s if s.starts_with('e') || s.starts_with('E') => {
            let exp: i32 = s[1..].parse().ok()?;
            10f64.powi(exp)
        }
        _ => return None,
    };
    if num.matches('.').count() > 1 {
        return None;
    }
    // Exact path for the overwhelmingly common integer + binary suffix
    // case, so `128Mi` does not go through f64 at all.
    if !num.contains('.') && multiplier.fract() == 0.0 && multiplier >= 1.0 {
        let n: u64 = num.parse().ok()?;
        return n.checked_mul(multiplier as u64);
    }
    let n: f64 = num.parse().ok()?;
    let bytes = n * multiplier;
    if !bytes.is_finite() || bytes < 0.0 {
        return None;
    }
    Some(bytes.floor() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(uid: &str, name: &str, id: u64) -> ContainerCompute {
        ContainerCompute {
            pod_uid: uid.into(),
            namespace: "ns".into(),
            pod_name: "pod".into(),
            container_name: name.into(),
            container_id: format!("cid-{id}"),
            pid: 1,
            cgroup_path: format!("kubepods.slice/pod{uid}.slice/cri-containerd-{id}.scope"),
            cgroup_id: id,
            resources: ResourceSpec::default(),
            node: "n".into(),
        }
    }

    #[test]
    fn insert_lookup_remove_round_trip() {
        let r = ComputeRegistry::new();
        let mut rx = r.subscribe();
        r.insert_container(container("u1", "api", 10));
        r.insert_container(container("u1", "sidecar", 11));
        r.insert_container(container("u2", "web", 20));
        r.insert_pod(PodCompute {
            pod_uid: "u1".into(),
            namespace: "ns".into(),
            pod_name: "pod".into(),
            pod_cgroup_path: "kubepods.slice/podu1.slice".into(),
            pod_cgroup_id: 9,
        });
        assert_eq!(r.lookup_cgroup(11).unwrap().container_name, "sidecar");
        assert_eq!(r.containers().len(), 3);
        assert_eq!(r.pods().len(), 1);
        let mut uids = r.pod_uids();
        uids.sort();
        assert_eq!(uids, vec!["u1", "u2"]);

        r.remove_pod("u1");
        assert!(r.lookup_cgroup(10).is_none());
        assert!(r.lookup_cgroup(11).is_none());
        assert!(r.lookup_cgroup(20).is_some());
        assert!(r.pods().is_empty());

        let mut seen = Vec::new();
        while let Ok(e) = rx.try_recv() {
            seen.push(e);
        }
        assert_eq!(
            seen,
            vec![
                ComputeRegistration::Added { cgroup_id: 10 },
                ComputeRegistration::Added { cgroup_id: 11 },
                ComputeRegistration::Added { cgroup_id: 20 },
                ComputeRegistration::Removed { cgroup_id: 10 },
                ComputeRegistration::Removed { cgroup_id: 11 },
            ]
        );
    }

    #[test]
    fn reinsert_is_idempotent_and_restart_retires_old_id() {
        // The 60 s resync re-registers every pod; that must not churn
        // the BPF tracked_cgroups map.
        let r = ComputeRegistry::new();
        let mut rx = r.subscribe();
        r.insert_container(container("u1", "api", 10));
        r.insert_container(container("u1", "api", 10));
        assert_eq!(
            rx.try_recv(),
            Ok(ComputeRegistration::Added { cgroup_id: 10 })
        );
        assert!(rx.try_recv().is_err());
        // Container restarted: same name, new scope, new id.
        r.insert_container(container("u1", "api", 12));
        assert_eq!(
            rx.try_recv(),
            Ok(ComputeRegistration::Removed { cgroup_id: 10 })
        );
        assert_eq!(
            rx.try_recv(),
            Ok(ComputeRegistration::Added { cgroup_id: 12 })
        );
        assert!(r.lookup_cgroup(10).is_none());
        assert_eq!(r.containers().len(), 1);
    }

    #[test]
    fn proc_cgroup_v2_line_is_picked_out_of_hybrid_and_pure_files() {
        let pure = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-deadbeef.scope\n";
        assert_eq!(
            parse_proc_cgroup_v2(pure).as_deref(),
            Some("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-deadbeef.scope")
        );
        let hybrid = "12:cpu,cpuacct:/kubepods/burstable/podabc/deadbeef\n\
                      3:memory:/kubepods/burstable/podabc/deadbeef\n\
                      0::/kubepods/burstable/podabc/deadbeef\n";
        assert_eq!(
            parse_proc_cgroup_v2(hybrid).as_deref(),
            Some("kubepods/burstable/podabc/deadbeef")
        );
        assert_eq!(parse_proc_cgroup_v2("12:cpu:/foo\n"), None);
        // Root cgroup.
        assert_eq!(parse_proc_cgroup_v2("0::/\n").as_deref(), Some(""));
    }

    #[test]
    fn pod_cgroup_is_the_parent_of_the_container_scope() {
        assert_eq!(
            pod_cgroup_path(
                "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-x.scope"
            )
            .as_deref(),
            Some("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice")
        );
        assert_eq!(
            pod_cgroup_path("kubepods/besteffort/podabc/x").as_deref(),
            Some("kubepods/besteffort/podabc")
        );
        assert_eq!(pod_cgroup_path("init.scope"), None);
    }

    #[test]
    fn cpu_quantities_parse_to_millis() {
        assert_eq!(parse_cpu_millis("100m"), Some(100));
        assert_eq!(parse_cpu_millis("1"), Some(1000));
        assert_eq!(parse_cpu_millis("2.5"), Some(2500));
        assert_eq!(parse_cpu_millis("0.5"), Some(500));
        assert_eq!(parse_cpu_millis(".25"), Some(250));
        assert_eq!(parse_cpu_millis("1.2345"), Some(1234));
        assert_eq!(parse_cpu_millis(" 250m "), Some(250));
        assert_eq!(parse_cpu_millis(""), None);
        assert_eq!(parse_cpu_millis("abc"), None);
        assert_eq!(parse_cpu_millis("1Gi"), None);
    }

    #[test]
    fn memory_quantities_parse_to_bytes() {
        assert_eq!(parse_memory_bytes("128Mi"), Some(128 * 1024 * 1024));
        assert_eq!(parse_memory_bytes("1Gi"), Some(1 << 30));
        assert_eq!(parse_memory_bytes("1G"), Some(1_000_000_000));
        assert_eq!(parse_memory_bytes("1000000"), Some(1_000_000));
        assert_eq!(parse_memory_bytes("512Ki"), Some(512 * 1024));
        assert_eq!(parse_memory_bytes("1.5Gi"), Some(3 * (1 << 29)));
        assert_eq!(parse_memory_bytes("1e6"), Some(1_000_000));
        assert_eq!(parse_memory_bytes("2Ti"), Some(2 << 40));
        assert_eq!(parse_memory_bytes(""), None);
        assert_eq!(parse_memory_bytes("Mi"), None);
        assert_eq!(parse_memory_bytes("1Xi"), None);
        assert_eq!(parse_memory_bytes("1.2.3"), None);
    }

    /// Verifies the `name_to_handle_at` id against `stat` on the cgroup
    /// root itself. kernfs ids carry the inode number in their low 32
    /// bits (with a generation above on 32-bit `ino_t`, and the whole id
    /// as the inode on 64-bit), so the low bits must agree either way.
    /// Skipped, not failed, on a host without cgroup v2.
    #[test]
    fn cgroup_id_matches_stat_inode_low_bits_on_cgroup_v2() {
        use std::os::unix::fs::MetadataExt;
        let root = Path::new("/sys/fs/cgroup");
        if !root.join("cgroup.controllers").exists() {
            eprintln!("skipping: /sys/fs/cgroup is not cgroup v2 here");
            return;
        }
        let id = match cgroup_id_for_path(root, "") {
            Ok(id) => id,
            Err(e)
                if e.raw_os_error() == Some(libc::EPERM)
                    || e.raw_os_error() == Some(libc::EACCES) =>
            {
                eprintln!("skipping: name_to_handle_at not permitted here ({e})");
                return;
            }
            Err(e) => panic!("name_to_handle_at on cgroup root: {e}"),
        };
        let ino = std::fs::metadata(root).unwrap().ino();
        assert_ne!(id, 0, "cgroup root id must not be 0");
        assert_eq!(
            id & 0xffff_ffff,
            ino & 0xffff_ffff,
            "handle id {id:#x} vs stat ino {ino:#x}"
        );
        // And a child, when one exists, gets a different id.
        if let Some(child) = std::fs::read_dir(root)
            .unwrap()
            .flatten()
            .find(|e| e.path().is_dir())
        {
            let rel = child.file_name().to_string_lossy().to_string();
            let cid = cgroup_id_for_path(root, &rel).unwrap();
            let cino = std::fs::metadata(child.path()).unwrap().ino();
            assert_ne!(cid, id);
            assert_eq!(cid & 0xffff_ffff, cino & 0xffff_ffff);
        }
    }

    #[test]
    fn cgroup_id_for_missing_path_is_an_error() {
        assert!(cgroup_id_for_path(Path::new("/nonexistent-kg"), "x").is_err());
    }
}
