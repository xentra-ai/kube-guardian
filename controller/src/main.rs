use anyhow::Result;
use dashmap::DashMap;
use std::{env, sync::Arc};
use tokio::sync::mpsc;

use tracing::info;

use kguardian::bpf::ebpf_handle;
use kguardian::log::init_logger;
use kguardian::network::{handle_network_events, handle_policy_drop_events, PolicyDropEvent};
use kguardian::seccomp_distributor::run as run_seccomp_distributor;
use kguardian::service_watcher::watch_service;
use kguardian::syscall::{
    handle_syscall_events, send_syscall_cache_periodically, SyscallEventData,
};
use kguardian::{
    error::Error, models::ContainerMap, network::NetworkEventData,
    pod_reconciler::reconcile_pods_task, pod_watcher::watch_pods,
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    init_logger();

    // Trim whitespace from required URL/identity env vars. Common
    // operator pastes embed a trailing newline or surrounding spaces;
    // pre-trim defends every downstream consumer instead of forcing
    // each (api_post_call, the reconciler, the pod_watcher, etc.) to
    // remember the same hardening. An empty-after-trim value still
    // counts as "not set" → clear error message.
    let node_name = env::var("CURRENT_NODE")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Custom("CURRENT_NODE environment variable not set".to_string()))?;

    let broker_url = env::var("API_ENDPOINT")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Custom("API_ENDPOINT environment variable not set".to_string()))?;

    // One-shot, fire-and-forget: derive this node's environment facts
    // (provider/distro/CNI/IP family/OS) and report them to the broker
    // for the anonymous telemetry check-in. Deliberately NOT part of
    // the try_join! fabric — telemetry must never take capture down.
    tokio::spawn(kguardian::node_facts::report_node_facts(
        node_name.clone(),
        broker_url.clone(),
    ));

    let excluded_namespaces: Vec<String> = kguardian::pod_watcher::parse_excluded_namespaces(
        &env::var("EXCLUDED_NAMESPACES").unwrap_or_else(|_| "kube-system,kguardian".to_string()),
    );

    // bool::from_str is strict — only lowercase "true"/"false".
    // parse_lenient_bool accepts case-insensitive variants and
    // tolerates surrounding whitespace, so "False"/"FALSE"/" true\n"
    // all do the right thing instead of silently falling back to
    // the default. Operator setting IGNORE_DAEMONSET_TRAFFIC=False
    // (intending to disable) used to flip back to the default true
    // — the opposite of their intent.
    let ignore_daemonset_traffic = kguardian::pod_watcher::parse_lenient_bool(
        &env::var("IGNORE_DAEMONSET_TRAFFIC").unwrap_or_default(),
        true,
    );

    // Syscall capture tier (SYSCALL_CAPTURE_LEVEL, default full) and the
    // names behind `custom` (SYSCALL_CUSTOM_LIST). Resolved to numbers
    // for THIS architecture here, once, and logged, so an operator can
    // see what each tier means on the node. Every tier is resolved
    // regardless of the cluster default because a pod annotation can
    // raise any workload to any tier.
    let capture_config = kguardian::capture_tiers::CaptureConfig::from_env();
    info!(
        level = %capture_config.level,
        custom_names = capture_config.custom_names.len(),
        "syscall capture level"
    );
    let cluster_capture_level = capture_config.level;
    let resolved_tiers = capture_config.resolve();

    let (tx, rx) = mpsc::channel(1000); // Use tokio's mpsc channel

    let (sender_ip, recv_ip) = mpsc::channel(1000); // Use tokio's mpsc channel

    // Shared inode -> pod map. NOTE: DashMap is sharded RwLocks, not lock-free.
    // Every subsystem below is joined into ONE task by try_join!, so a shard
    // guard held across an .await blocks the whole controller permanently.
    // Read it only via models::lookup_pod. See ContainerMap for the detail.
    let container_map: ContainerMap = Arc::new(DashMap::new());
    let pod_c = Arc::clone(&container_map);
    let network_map = Arc::clone(&container_map);
    let syscall_map = Arc::clone(&container_map);

    let pods = watch_pods(
        node_name.clone(),
        tx,
        pod_c,
        &excluded_namespaces,
        sender_ip,
        ignore_daemonset_traffic,
        cluster_capture_level,
    );
    info!("Ignoring namespaces: {:?}", excluded_namespaces);

    let service = watch_service();

    // Start pod reconciliation task
    let pod_reconciler = reconcile_pods_task(node_name, broker_url);

    let (network_event_sender, network_event_receiver) = mpsc::channel::<NetworkEventData>(1000);
    let (syscall_event_sender, syscall_event_receiver) = mpsc::channel::<SyscallEventData>(1000);
    let (netpolicy_drop_sender, netpolicy_drop_receiver) = mpsc::channel::<PolicyDropEvent>(1000);

    let network_event_handler = handle_network_events(network_event_receiver, network_map);
    let netpolicy_drop_handler =
        handle_policy_drop_events(netpolicy_drop_receiver, Arc::clone(&container_map));
    let syscall_event_handler = handle_syscall_events(syscall_event_receiver, syscall_map);

    let ebpf_handle = ebpf_handle(
        network_event_sender,
        syscall_event_sender,
        netpolicy_drop_sender,
        rx,
        recv_ip,
        ignore_daemonset_traffic,
        resolved_tiers,
    );

    let syscall_recorder = send_syscall_cache_periodically();

    // Writes broker-generated per-workload seccomp profiles onto this
    // node. No-ops unless SECCOMP_DISTRIBUTE=true; best-effort, so a
    // failure here never restarts the controller.
    let seccomp_distributor = run_seccomp_distributor();

    // Graceful shutdown on SIGTERM/SIGINT
    let shutdown = async {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");
        let sigint = tokio::signal::ctrl_c();
        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM, shutting down"),
            _ = sigint => info!("Received SIGINT, shutting down"),
        }
        Ok::<(), Error>(())
    };

    // Wait for all tasks to complete or shutdown signal.
    //
    // `try_join!` means the FIRST subsystem to return `Err` tears down
    // every other one. That is deliberate for the ones left here, and
    // it is no longer a trapdoor for the apiserver watches: `watch_pods`
    // and `watch_service` handle their stream errors in-band and never
    // return at all now (see watch_loop). Before that, a single dropped
    // apiserver connection resolved their `try_for_each`, propagated a
    // `?` through here, and took kernel-side capture down with it — 26
    // of 42 Controllers exited that way inside six minutes on
    // 2026-09-04, each losing a `connections` LRU, its `inode_num`
    // registrations and its tier allowlists with nothing to backfill
    // them. Watch failures degrade the watch; they do not stop capture.
    //
    // `ebpf_handle` stays in the join on purpose, and the asymmetry is
    // the point. Kernel-side capture is the product: a Controller whose
    // eBPF loader has died is not degraded, it is blind, and a blind
    // Controller that keeps running turns kguardian's core guarantee
    // (observed-absence means safe-to-deny) into a lie that nothing
    // marks. Exiting non-zero is the only signal that reaches an
    // operator today — there is no readiness endpoint on this
    // DaemonSet — so a capture failure must still restart the pod.
    // Pulling it out of the join would buy nothing and hide that.
    //
    // The remaining hazard is that all of these are polled on ONE task,
    // so a blocking mistake anywhere wedges everything. That is #1346
    // and is not addressed here.
    tokio::select! {
        result = async {
            tokio::try_join!(
                service,
                pods,
                network_event_handler,
                syscall_event_handler,
                netpolicy_drop_handler,
                syscall_recorder,
                seccomp_distributor,
                pod_reconciler,
                async { ebpf_handle.await? }
            )
        } => { result?; }
        // The watches are infinite by construction now, so the join
        // branch above no longer completes on its own in the normal
        // case: this arm is the ordinary way the process ends. Both
        // futures are polled on this task, so completing here drops the
        // join and cancels every subsystem with it.
        _ = shutdown => {
            info!("Graceful shutdown complete");
        }
    }
    Ok(())
}
