//! Supervision for the Controller's long-lived apiserver watches.
//!
//! A watch is not a request. It is the Controller's only live view of
//! the cluster, and it is expected to outlive every apiserver
//! disruption the cluster will ever have. This module owns the loop
//! that makes that true, so `pod_watcher` and `service_watcher` cannot
//! drift apart on it.
//!
//! ## The incident this exists for
//!
//! On 2026-09-04, 26 of 42 Controllers exited inside a six-minute
//! window (23:15-23:21Z), every one with
//! `KubeWatcherError { source: WatchStartFailed(Service(hyper::Error(IncompleteMessage))) }`
//! and exit code 1. Both watchers were built as
//!
//! ```ignore
//! watcher(api, cfg).applied_objects().default_backoff().try_for_each(..)
//! ```
//!
//! which looks like it retries and does not. `try_for_each`
//! short-circuits on the first `Err`: it resolves immediately and
//! *drops* the stream, taking the `StreamBackoff` — and the sleep it
//! had just armed — with it. kube's own `watcher` documentation spells
//! this out: "some TryStream combinators (such as try_for_each and
//! try_concat) will terminate eagerly as soon as they receive an Err."
//! So not one retry ever happened. The `.default_backoff()` in that
//! chain was decorative; the six minutes was the length of the
//! apiserver disruption, not a backoff clock (kube 4.2.0's
//! `DefaultBackoff` is built `.without_max_times()` with no total
//! delay — it would have retried forever if anything had polled it).
//! The `?` then propagated into main's `try_join!`, which also holds
//! the eBPF handle, so one dropped apiserver connection tore down
//! kernel-side capture too.
//!
//! That is the wrong trade for this DaemonSet. A restart cannot
//! rebuild what it destroys: the `connections` LRU, the `inode_num`
//! registrations and the tier allowlists all come back empty, and
//! nothing backfills the traffic that happened in the gap. kguardian's
//! guarantee is that observed-absence means safe-to-deny, so a silent
//! capture hole does not merely lose data — it yields under-permissive
//! policies and incomplete seccomp profiles that fail later, in
//! someone else's workload. "The fleet recovered on its own" is the
//! hazard here, not the mitigation: 26 nodes lost capture, came back
//! clean, and nothing marked the resulting data as holed.
//!
//! Kernel-side capture has no dependency on apiserver reachability, so
//! a watcher outage must degrade the watcher and nothing else.
//!
//! ## What this loop guarantees
//!
//! * An `Err` item is logged and the stream keeps being polled, so
//!   kube's `StreamBackoff` sleep is honoured and the watch reconnects.
//! * A watch that stays broken escalates from `warn` to `error`, so a
//!   permanently-wedged watcher cannot masquerade as a healthy one.
//! * The loop is infinite by construction and holds no blocking work,
//!   so main's shutdown `select!` can still cancel it on SIGTERM.

use futures::{Stream, StreamExt};
use std::{
    fmt::Display,
    future::Future,
    pin::pin,
    time::{Duration, Instant},
};
use tracing::{error, info, warn};

/// Consecutive failures before a watch stops being "a blip" and starts
/// being "broken", i.e. escalates from `warn` to `error`.
///
/// kube 4.2.0's `DefaultBackoff` sleeps ~0.8s, 1.6s, 3.2s, 6.4s, 12.8s,
/// 25.6s then 30s per retry (jittered, uncapped in attempts), and the
/// `ResetTimerBackoff` around it restarts that ladder after 120s
/// without an error. Eight back-to-back failures is therefore roughly
/// two minutes of a watch that is not recovering — comfortably past a
/// rolling apiserver restart or a leader election, and worth waking
/// someone for. The 2026-09-04 disruption ran six minutes, so it would
/// have crossed this line and said so.
const ESCALATE_AFTER: u32 = 8;

/// Once escalated, re-emit the `error` every this many further
/// failures — ~30 minutes at the 30s backoff ceiling. An alert rule
/// keyed on a log line needs it to recur; the node's disk needs it not
/// to recur every 30 seconds for a week.
const ESCALATE_EVERY: u32 = 60;

/// Ceiling on the rebuild backoff (see `rebuild_delay`).
const REBUILD_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// What to log for a watch failure, given how many have arrived
/// back-to-back with no successful event in between.
///
/// Pure, so the thresholds are unit-testable and cannot silently
/// regress into either "log nothing, look healthy" or "log every 30
/// seconds forever". Same shape as `bpf::PollErrorAction`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WatchErrorAction {
    /// A blip. kube's `StreamBackoff` is already sleeping before the
    /// reconnect, so one `warn` line is the whole story.
    Warn,
    /// The streak crossed `ESCALATE_AFTER`: this watch has been failing
    /// for minutes, not seconds. Log at `error` so it reaches whatever
    /// the operator alerts on.
    Escalate,
    /// Still broken, but already reported. Stay quiet.
    Suppress,
}

/// Map a 1-based consecutive-failure count to what should be logged.
pub(crate) fn watch_error_action(consecutive: u32) -> WatchErrorAction {
    if consecutive < ESCALATE_AFTER {
        WatchErrorAction::Warn
    } else if (consecutive - ESCALATE_AFTER).is_multiple_of(ESCALATE_EVERY) {
        WatchErrorAction::Escalate
    } else {
        WatchErrorAction::Suppress
    }
}

/// How long to wait before rebuilding a watch stream that ended, given
/// how many times it has ended back-to-back (0-based): 1s, 2s, 4s …
/// capped at `REBUILD_BACKOFF_MAX`. Pure so the ladder is testable.
fn rebuild_delay(consecutive_ends: u32) -> Duration {
    Duration::from_secs(1u64 << consecutive_ends.min(6)).min(REBUILD_BACKOFF_MAX)
}

/// Drive a watch stream for the lifetime of the process.
///
/// **Never returns.** The only ways out are main's shutdown `select!`
/// cancelling the future, or the process exiting. Callers that need a
/// `Result` (to sit in a `try_join!`) should wrap the call in an async
/// block that appends `Ok(())` after it.
///
/// `make_stream` is called once up front and again whenever the stream
/// ends, so it must rebuild from cloned handles rather than move them.
/// `on_object` is awaited per decoded object; anything it needs must be
/// cloned into the future it returns, since the future cannot borrow
/// from the closure.
///
/// Errors are handled in-band and never propagated: see the module
/// docs for why an apiserver blip must not be allowed to reach main.
pub(crate) async fn run_watch<T, E, S, MkStream, F, Fut>(
    watch: &'static str,
    mut make_stream: MkStream,
    mut on_object: F,
) where
    E: Display,
    S: Stream<Item = Result<T, E>>,
    MkStream: FnMut() -> S,
    F: FnMut(T) -> Fut,
    Fut: Future<Output = ()>,
{
    // Consecutive failures since the last successful event. Separate
    // counters because the two failure modes deserve different words
    // in the log, but they share one escalation ladder and both reset
    // on any object arriving.
    let mut consecutive_errors: u32 = 0;
    let mut consecutive_ends: u32 = 0;
    let mut degraded_since: Option<Instant> = None;

    info!(watch, "watch started");

    loop {
        let mut stream = pin!(make_stream());

        while let Some(item) = stream.next().await {
            match item {
                Ok(obj) => {
                    // Recovery is worth one line at info: it is the
                    // other half of the escalation above, and without
                    // it an operator staring at an `error` has no way
                    // to tell "still broken" from "fixed itself".
                    if let Some(since) = degraded_since.take() {
                        info!(
                            watch,
                            errors = consecutive_errors,
                            stream_ends = consecutive_ends,
                            degraded_secs = since.elapsed().as_secs(),
                            "watch recovered; events are flowing again"
                        );
                    }
                    consecutive_errors = 0;
                    consecutive_ends = 0;
                    on_object(obj).await;
                }
                // The whole point of the fix: log it and keep polling.
                // The next poll is what lets kube's StreamBackoff sleep
                // and then restart the watch from the last resource
                // version. Returning (or `?`-ing) here is what killed
                // 26 nodes' capture on 2026-09-04.
                Err(e) => {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    degraded_since.get_or_insert_with(Instant::now);
                    match watch_error_action(consecutive_errors) {
                        WatchErrorAction::Warn => warn!(
                            watch,
                            consecutive = consecutive_errors,
                            "watch error (backing off, will retry): {e}"
                        ),
                        WatchErrorAction::Escalate => error!(
                            watch,
                            consecutive = consecutive_errors,
                            degraded_secs = degraded_since
                                .map(|s| s.elapsed().as_secs())
                                .unwrap_or_default(),
                            "watch has been failing continuously; this node's \
                             observations are incomplete for the duration: {e}"
                        ),
                        WatchErrorAction::Suppress => {}
                    }
                }
            }
        }

        // The stream ended. With kube 4.2.0's `DefaultBackoff` that
        // cannot happen — its `ExponentialBackoff` is built
        // `.without_max_times()`, so `next()` never yields `None` and
        // `StreamBackoff` never reaches its `GivenUp` state — but a
        // kube upgrade could change that, and the failure would be
        // invisible. Do not return: main's `try_join!` would sit
        // forever on a watch that is silently dead. Do not error out
        // either: that restarts the pod and destroys exactly the kernel
        // state this module exists to protect. Back off, rebuild, carry
        // on — the same conclusion the SeccompProfile watcher reached
        // in seccomp_distributor::run.
        let delay = rebuild_delay(consecutive_ends);
        consecutive_ends = consecutive_ends.saturating_add(1);
        degraded_since.get_or_insert_with(Instant::now);
        match watch_error_action(consecutive_ends) {
            WatchErrorAction::Warn => warn!(
                watch,
                attempt = consecutive_ends,
                delay_secs = delay.as_secs(),
                "watch stream ended; rebuilding after backoff"
            ),
            WatchErrorAction::Escalate => error!(
                watch,
                attempt = consecutive_ends,
                delay_secs = delay.as_secs(),
                "watch stream keeps ending; this node's observations are \
                 incomplete until it stays up"
            ),
            WatchErrorAction::Suppress => {}
        }
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{stream, TryStreamExt};
    use std::sync::{Arc, Mutex};

    type Seen = Arc<Mutex<Vec<u32>>>;
    type TestStream = futures::stream::BoxStream<'static, Result<u32, String>>;

    fn seen() -> Seen {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn got(seen: &Seen) -> Vec<u32> {
        seen.lock().unwrap().clone()
    }

    /// The defect, pinned. This is the exact combinator the two
    /// watchers used before this module existed, over a stream that
    /// has plenty left to give after its first error.
    ///
    /// It is here so the test below cannot quietly become a tautology:
    /// if someone "simplifies" `run_watch` back into `try_for_each`,
    /// this test still passes and the next one fails, which is the
    /// right way round.
    #[tokio::test]
    async fn try_for_each_abandons_the_stream_at_the_first_error() {
        let seen = seen();
        let sink = Arc::clone(&seen);
        let result = stream::iter(vec![
            Ok(1u32),
            Err("apiserver hung up".to_string()),
            Ok(2),
            Ok(3),
        ])
        .try_for_each(move |v| {
            sink.lock().unwrap().push(v);
            std::future::ready(Ok(()))
        })
        .await;

        assert!(result.is_err(), "try_for_each surfaces the error");
        assert_eq!(
            got(&seen),
            vec![1],
            "try_for_each short-circuits: everything after the first Err is \
             dropped on the floor, stream and armed backoff sleep included"
        );
    }

    /// The fix, proven: the same error, in the middle of the same
    /// stream, and the consumer keeps going.
    #[tokio::test]
    async fn a_stream_error_does_not_stop_the_consumer() {
        let seen = seen();
        let sink = Arc::clone(&seen);
        let mut built = 0u32;

        let fut = run_watch(
            "test",
            move || -> TestStream {
                built += 1;
                if built == 1 {
                    stream::iter(vec![
                        Ok(1u32),
                        Err("apiserver hung up".to_string()),
                        Ok(2),
                        Err("apiserver hung up again".to_string()),
                        Err("and again".to_string()),
                        Ok(3),
                    ])
                    .boxed()
                } else {
                    stream::pending().boxed()
                }
            },
            move |v| {
                sink.lock().unwrap().push(v);
                std::future::ready(())
            },
        );

        // One poll drains every ready item and then parks on the
        // rebuild sleep, so this is deterministic — no timing.
        let mut fut = pin!(fut);
        assert!(
            futures::poll!(fut.as_mut()).is_pending(),
            "run_watch must never complete on its own"
        );
        assert_eq!(
            got(&seen),
            vec![1, 2, 3],
            "every object after an error must still be delivered"
        );
    }

    /// A stream that ends is rebuilt rather than being allowed to leave
    /// the watch silently dead (or to restart the pod and wipe the
    /// kernel-side capture state).
    #[tokio::test]
    async fn a_stream_that_ends_is_rebuilt_and_keeps_consuming() {
        let seen = seen();
        let sink = Arc::clone(&seen);
        let mut built = 0u32;

        let fut = run_watch(
            "test",
            move || -> TestStream {
                built += 1;
                match built {
                    1 => stream::iter(vec![Ok(1u32)]).boxed(),
                    2 => stream::iter(vec![Ok(2u32)]).boxed(),
                    _ => stream::pending().boxed(),
                }
            },
            move |v| {
                sink.lock().unwrap().push(v);
                std::future::ready(())
            },
        );

        let mut fut = pin!(fut);
        assert!(futures::poll!(fut.as_mut()).is_pending());
        assert_eq!(got(&seen), vec![1], "first stream consumed, rebuild armed");

        // Real time, because the first rung of the rebuild ladder is a
        // one-second sleep and the crate does not enable tokio's
        // test-util clock. One slow test is worth proving the rebuild
        // actually fires rather than asserting on rebuild_delay alone.
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(futures::poll!(fut.as_mut()).is_pending());
        assert_eq!(
            got(&seen),
            vec![1, 2],
            "the rebuilt stream must be consumed too"
        );
    }

    /// Shutdown. The loop is infinite by construction now, so main's
    /// `select!` against SIGTERM is the only thing that stops it — this
    /// pins both halves of that: the loop yields (it does not starve
    /// the other select branch), and once cancelled it really stops.
    #[tokio::test]
    async fn the_watch_loop_yields_to_shutdown_and_stops_when_cancelled() {
        let seen = seen();
        let sink = Arc::clone(&seen);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<u32, String>>();
        tx.send(Ok(1)).unwrap();
        tx.send(Err("apiserver hung up".to_string())).unwrap();
        tx.send(Ok(2)).unwrap();

        let mut rx = Some(rx);
        let watch = run_watch(
            "test",
            move || -> TestStream {
                match rx.take() {
                    // A live sender keeps this stream pending forever
                    // once drained — an idle, healthy watch.
                    Some(rx) => stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|item| (item, rx))
                    })
                    .boxed(),
                    None => stream::pending().boxed(),
                }
            },
            move |v| {
                sink.lock().unwrap().push(v);
                std::future::ready(())
            },
        );

        // `biased` polls the watch first, so the shutdown branch only
        // wins if the watch genuinely yielded — which is the property
        // under test.
        let winner = tokio::select! {
            biased;
            _ = watch => "watch",
            _ = std::future::ready(()) => "shutdown",
        };

        assert_eq!(
            winner, "shutdown",
            "an endless watch must still let the shutdown branch run"
        );
        assert_eq!(got(&seen), vec![1, 2], "drained past the error first");

        // The receiver lived inside the watch future, so select!
        // dropped it along with the loop. A send that has nowhere to
        // go is the proof that the cancelled watch really stopped,
        // rather than merely stopping its logging.
        assert!(
            tx.send(Ok(3)).is_err(),
            "a cancelled watch must have dropped its stream"
        );
        tokio::task::yield_now().await;
        assert_eq!(
            got(&seen),
            vec![1, 2],
            "a cancelled watch must not keep consuming"
        );
    }

    #[test]
    fn error_action_warns_until_the_streak_looks_permanent() {
        for n in 1..ESCALATE_AFTER {
            assert_eq!(watch_error_action(n), WatchErrorAction::Warn, "n={n}");
        }
    }

    #[test]
    fn error_action_escalates_once_then_stays_quiet() {
        assert_eq!(
            watch_error_action(ESCALATE_AFTER),
            WatchErrorAction::Escalate
        );
        for n in ESCALATE_AFTER + 1..ESCALATE_AFTER + ESCALATE_EVERY {
            assert_eq!(watch_error_action(n), WatchErrorAction::Suppress, "n={n}");
        }
    }

    #[test]
    fn error_action_re_escalates_so_an_alert_keeps_firing() {
        // A watch broken for a week must not go silent after one line,
        // and must not write one line every 30 seconds either.
        assert_eq!(
            watch_error_action(ESCALATE_AFTER + ESCALATE_EVERY),
            WatchErrorAction::Escalate
        );
        assert_eq!(
            watch_error_action(ESCALATE_AFTER + 2 * ESCALATE_EVERY),
            WatchErrorAction::Escalate
        );
    }

    #[test]
    fn rebuild_delay_doubles_and_caps() {
        assert_eq!(rebuild_delay(0), Duration::from_secs(1));
        assert_eq!(rebuild_delay(1), Duration::from_secs(2));
        assert_eq!(rebuild_delay(4), Duration::from_secs(16));
        // Never hot-spins, never waits longer than a minute.
        for n in 6..64 {
            assert_eq!(rebuild_delay(n), REBUILD_BACKOFF_MAX, "n={n}");
        }
    }
}
