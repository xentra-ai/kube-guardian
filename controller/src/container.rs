use crate::PodInspect;
use containerd_client::{
    connect,
    services::v1::{tasks_client::TasksClient, GetRequest},
    tonic::{transport::Channel, Request},
    with_namespace,
};
use procfs::process::Process;
use regex::Regex;
use std::ffi::OsString;
use std::time::Duration;
use tracing::*;

static REGEX_CONTAINERD: &str = "containerd://(?P<container_id>[0-9a-zA-Z]*)";

/// Ceiling on establishing the containerd gRPC channel.
///
/// `containerd_client::connect` builds its `Endpoint` from
/// `Endpoint::try_from("http://[::]")` and sets neither `.timeout()`
/// nor `.connect_timeout()` (verified against containerd-client 0.9.0),
/// so the await it hands back has no deadline of its own.
///
/// Measured, so the bound is not folklore: the two wedged-daemon
/// shapes reachable in a test — a listener that accepts and never
/// speaks, and one whose accept backlog is saturated — both resolve
/// here rather than hanging. The HTTP/2 handshake completes on the
/// client preface without waiting for the server's SETTINGS frame, and
/// a full backlog surfaces as an immediate `EAGAIN`. So this ceiling
/// is not the one that was losing pod ingestion; `RPC_TIMEOUT` is (see
/// the tests). It stays because the call is still unbounded by
/// construction — a path lookup stalling on the filesystem holding the
/// socket, or a connector change upstream, puts the hang back — and a
/// two-second ceiling on a same-node unix socket that a healthy
/// containerd answers in single-digit milliseconds costs nothing.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Ceiling on the `Tasks.Get` RPC itself, and the load-bearing one.
///
/// This is the await that parks forever against a containerd that is
/// alive, holding its socket, and answering nothing — a daemon blocked
/// behind a stuck shim. It sits on the pod-registration path, awaited
/// sequentially per container, per pod, per 60s resync pass, so one
/// wedged daemon stopped ALL pod ingestion for the life of the
/// process: no netns inode reached the ContainerMap, and every later
/// pod's traffic was attributed to nothing.
///
/// Five seconds is well past containerd's own behaviour for a local
/// task lookup and still bounded. A tonic `Endpoint::timeout` would
/// cover this in the transport (the channel stack applies it via its
/// `GrpcTimeout` layer), but reaching it means rebuilding the endpoint
/// and its unix connector here, which pulls `tower` and `hyper-util`
/// in as direct dependencies to reimplement what `connect` already
/// does. `tokio::time::timeout` bounds the same await with no new
/// dependencies and, unlike the transport setting, is exercisable in a
/// unit test.
pub(crate) const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Parse a Kubernetes pod-status containerID URL.
///
/// Expects `containerd://<id>` — only the containerd runtime is
/// supported today. Returns the bare container ID, or None when the
/// input doesn't match (cri-o:// or docker:// prefixes, malformed
/// strings, etc.). A non-match is non-fatal at the call site — pods
/// using other runtimes are simply skipped.
pub(crate) fn parse_container_id(s: &str) -> Option<String> {
    let re = Regex::new(REGEX_CONTAINERD).ok()?;
    re.captures(s)
        .and_then(|c| c.name("container_id"))
        .map(|m| m.as_str().to_string())
        .filter(|s| !s.is_empty())
}

/// Containerd socket path, trimmed.
///
/// Trim — a trailing newline from `CONTAINERD_SOCK="/run/...\n"` would
/// break the unix-socket connect with a confusing "No such file or
/// directory" error far from the env read.
pub(crate) fn containerd_sock() -> String {
    std::env::var("CONTAINERD_SOCK")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "/run/containerd/containerd.sock".to_string())
}

/// Open a containerd channel, or give up after `timeout`.
///
/// Split out with an explicit timeout argument so the bound itself is
/// testable against a socket that accepts and never speaks — the exact
/// shape that used to park the pod watcher forever. See
/// [`CONNECT_TIMEOUT`].
pub(crate) async fn connect_containerd(sock_path: &str, timeout: Duration) -> Option<Channel> {
    match tokio::time::timeout(timeout, connect(sock_path)).await {
        Ok(Ok(channel)) => Some(channel),
        Ok(Err(err)) => {
            error!("Failed to connect to containerd socket: {:?}", err);
            None
        }
        Err(_) => {
            error!(
                sock = sock_path,
                timeout_secs = timeout.as_secs(),
                "containerd did not complete the connection within the timeout; skipping \
                 this container. Pod ingestion continues — before this bound existed the \
                 await never returned and every subsequent pod on this node went \
                 unobserved."
            );
            None
        }
    }
}

impl PodInspect {
    pub async fn get_pod_inspect(self, container_id: &str) -> Option<PodInspect> {
        let container_id = parse_container_id(container_id)?;
        let sock_path = containerd_sock();
        let channel = connect_containerd(&sock_path, CONNECT_TIMEOUT).await?;
        Some(
            self.set_container_id(container_id)
                .get_pid(channel)
                .await
                .get_net_namespace_id(),
        )
    }

    fn set_container_id(mut self, container_id: String) -> Self {
        self.container_id = Some(container_id);
        self
    }

    pub(crate) async fn get_pid(self, channel: Channel) -> Self {
        self.get_pid_bounded(channel, RPC_TIMEOUT).await
    }

    /// `get_pid` with the RPC ceiling passed in, so a test can hold a
    /// containerd that never answers without waiting [`RPC_TIMEOUT`]
    /// for the assertion.
    async fn get_pid_bounded(mut self, channel: Channel, rpc_timeout: Duration) -> Self {
        let mut client = TasksClient::new(channel.clone());

        // get_pid is only reached after set_container_id has populated
        // container_id, so the prior .unwrap() was safe in practice —
        // but a refactor that called get_pid in another path would
        // panic the spawn_blocking thread. Fail-soft: clone the value
        // if present, else short-circuit by leaving pid unset.
        let container_id = match self.container_id.clone() {
            Some(id) => id,
            None => {
                error!("get_pid called without a container id; pid stays unset");
                return self;
            }
        };
        let req = GetRequest {
            container_id,
            ..Default::default()
        };

        let req = with_namespace!(req, "k8s.io");
        // Bounded: `client.get(req)` is an ordinary tonic call with no
        // deadline of its own, and a containerd whose task service is
        // blocked behind a stuck shim answers it never. This await sits
        // on the pod-registration path, so an unbounded one stops every
        // later pod from being registered — the netns inode never lands
        // in the ContainerMap, and its traffic is attributed to nothing.
        match tokio::time::timeout(rpc_timeout, client.get(req)).await {
            Ok(Ok(resp)) => {
                let container_resp = resp.into_inner();
                self.pid = container_resp.process.map(|p| p.pid);
            }
            Ok(Err(err)) => {
                error!(
                    "Failed to get container response for container id {:?}, {:?}",
                    self.container_id, err
                );
                self.pid = None;
            }
            Err(_) => {
                error!(
                    container_id = ?self.container_id,
                    timeout_secs = rpc_timeout.as_secs(),
                    "containerd Tasks.Get did not answer within the timeout; pid stays \
                     unset and this container is skipped until the next resync"
                );
                self.pid = None;
            }
        }
        self
    }

    fn get_net_namespace_id(mut self) -> Self {
        if let Some(pid) = self.pid {
            if let Ok(process) = Process::new(pid as i32) {
                if let Ok(ns) = process.namespaces() {
                    if let Some(netns) = ns.0.get(&OsString::from("net")) {
                        self.inode_num = Some(netns.identifier);
                    }
                }
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unlinks the socket path on drop so a failing test doesn't leave
    /// litter behind in the temp dir.
    struct TempSock(String);
    impl Drop for TempSock {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// A containerd that is alive and holding its socket, and answers
    /// nothing: bound, listening, never accepting. This is the shape of
    /// a daemon wedged behind a stuck shim — the failure the pod
    /// watcher actually met, as opposed to a daemon that is simply
    /// down (which refuses the connection and fails fast).
    ///
    /// Both handles must be kept alive by the caller: the listener
    /// holds the socket bound, `TempSock` unlinks it afterwards.
    fn silent_containerd() -> (std::os::unix::net::UnixListener, String, TempSock) {
        let path = format!(
            "{}/kguardian-silent-containerd-{}-{:?}.sock",
            std::env::temp_dir().display(),
            std::process::id(),
            std::thread::current().id(),
        );
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path)
            .expect("bind a unix socket in the temp dir");
        (listener, path.clone(), TempSock(path))
    }

    /// A `Tasks.Get` for a plausible container id, built exactly as
    /// `get_pid_bounded` builds it.
    fn task_get_request() -> Request<GetRequest> {
        let req = GetRequest {
            container_id: "a".repeat(64),
            ..Default::default()
        };
        with_namespace!(req, "k8s.io")
    }

    /// The defect, pinned, and located.
    ///
    /// Measured here rather than assumed: against a containerd that
    /// holds its socket and answers nothing, `connect` RESOLVES — the
    /// HTTP/2 handshake completes as soon as the client preface is
    /// flushed and never waits for the server's SETTINGS frame — and
    /// it is `client.get(req)` that parks forever. Neither call had a
    /// deadline of its own, so this is where all pod ingestion stopped:
    /// the await sits on the registration path, sequentially, per
    /// container, per pod, per 60s resync pass.
    #[tokio::test]
    async fn the_raw_task_rpc_never_returns_against_a_silent_containerd() {
        let (_listener, path, _cleanup) = silent_containerd();

        let channel = connect(&path)
            .await
            .expect("a listening socket yields a channel even when the daemon is silent");
        let mut client = TasksClient::new(channel);

        let outcome =
            tokio::time::timeout(Duration::from_millis(750), client.get(task_get_request())).await;

        assert!(
            outcome.is_err(),
            "the Tasks.Get RPC is expected to be unbounded here; if this ever resolves, \
             containerd-client or tonic has started applying a deadline and the constants \
             in this module should be revisited"
        );
    }

    /// The fix, through the production code path: the same silent
    /// containerd, and `get_pid` gives up instead of parking. The lower
    /// bound on the elapsed time is the point — it proves the RPC
    /// really did hang and really was cut off, rather than erroring
    /// out for some unrelated reason and passing by accident.
    #[tokio::test]
    async fn a_silent_containerd_is_cut_off_at_the_rpc_ceiling() {
        let (_listener, path, _cleanup) = silent_containerd();

        // The connect half stays fast; the ceiling on it must not have
        // turned an ordinary dial into a stall.
        let started = tokio::time::Instant::now();
        let channel = connect_containerd(&path, CONNECT_TIMEOUT)
            .await
            .expect("a listening socket yields a channel");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "connecting to a listening socket must stay fast; took {:?}",
            started.elapsed()
        );

        let ceiling = Duration::from_millis(300);
        let started = tokio::time::Instant::now();
        let inspect = PodInspect {
            container_id: Some("a".repeat(64)),
            ..Default::default()
        }
        .get_pid_bounded(channel, ceiling)
        .await;

        assert!(
            inspect.pid.is_none(),
            "a timed-out RPC must leave pid unset rather than inventing one"
        );
        assert!(
            started.elapsed() >= ceiling,
            "the RPC must actually have hung and been cut off, not failed early; took {:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "and it must be cut off at the ceiling, not later; took {:?}",
            started.elapsed()
        );
    }

    /// The ceilings are a pod-registration budget, not a general
    /// timeout. `pod_watcher::process_container_ids` walks a pod's
    /// containers serially, so the worst an unresponsive daemon can
    /// cost one resync pass is containers x (connect + rpc). That has
    /// to stay well inside the 60s resync interval, or a single bad pod
    /// starves the pass that was meant to be the safety net.
    #[test]
    fn the_containerd_ceilings_stay_inside_a_resync_pass() {
        assert!(
            CONNECT_TIMEOUT + RPC_TIMEOUT <= Duration::from_secs(10),
            "a per-container budget of {:?} leaves too little of the 60s resync interval \
             for a pod with several containers",
            CONNECT_TIMEOUT + RPC_TIMEOUT
        );
    }

    /// A socket that is simply absent still fails fast and quietly —
    /// the connect ceiling must not have turned an ordinary error into
    /// a two-second stall on every container of every pod.
    #[tokio::test]
    async fn a_missing_socket_still_fails_immediately() {
        let started = tokio::time::Instant::now();
        let channel = connect_containerd(
            "/nonexistent/kguardian/containerd.sock",
            Duration::from_secs(2),
        )
        .await;

        assert!(channel.is_none());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "a missing socket is an error, not a timeout; took {:?}",
            started.elapsed()
        );
    }
    // parse_container_id is the gate that decides which pods we can
    // observe. A regression here either drops valid pods (we lose
    // visibility) or accepts garbage (we make containerd RPCs with
    // bad IDs, log noise).

    #[test]
    fn parse_extracts_id_from_containerd_url() {
        // 64-char hex is the canonical containerd ID shape.
        let id = "a".repeat(64);
        let url = format!("containerd://{id}");
        assert_eq!(parse_container_id(&url).as_deref(), Some(id.as_str()));
    }

    #[test]
    fn parse_accepts_alphanumeric_id() {
        // Mixed alphanumeric (rare but legal under the regex character class).
        assert_eq!(
            parse_container_id("containerd://Abc123Xyz").as_deref(),
            Some("Abc123Xyz"),
        );
    }

    #[test]
    fn parse_rejects_empty_id_after_prefix() {
        // `containerd://` with nothing after means no container ID — must
        // not produce Some("") which would be sent to the containerd
        // socket and 404 noisily.
        assert_eq!(parse_container_id("containerd://"), None);
    }

    #[test]
    fn parse_rejects_other_runtimes() {
        // Pods on cri-o, docker (legacy), or any other runtime should
        // be skipped, not misparsed.
        assert_eq!(parse_container_id("cri-o://abc123"), None);
        assert_eq!(parse_container_id("docker://abc123"), None);
        assert_eq!(parse_container_id("rkt://abc123"), None);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse_container_id(""), None);
        assert_eq!(parse_container_id("just some text"), None);
        assert_eq!(parse_container_id("https://example.com"), None);
    }

    #[test]
    fn parse_stops_at_non_alphanumeric() {
        // The regex character class is [0-9a-zA-Z]*, so the first
        // non-alphanumeric char terminates the capture. A path like
        // `containerd://abc/def` yields just `abc` — that's fine,
        // but pin the contract.
        assert_eq!(
            parse_container_id("containerd://abc/def").as_deref(),
            Some("abc"),
        );
        assert_eq!(
            parse_container_id("containerd://abc-def").as_deref(),
            Some("abc"),
        );
    }
}
