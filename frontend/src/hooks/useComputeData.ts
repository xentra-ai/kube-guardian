import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ComputeUnsupportedError, apiClient } from '../services/api';
import type { ComputeContainer, ComputeFinding, ComputeFindingsMeta, ComputeNode, ComputeSample } from '../types/compute';
import { COMPUTE_HISTORY_SAMPLES, RingBuffer, podLevelSample, podNameKey } from '../utils/compute';

export const COMPUTE_POLL_MS = 5_000;
export const COMPUTE_FINDINGS_POLL_MS = 15_000;

export interface UseComputeDataOptions {
  /** Latest-rows poll interval; ≤ 0 disables polling (fetch once). */
  pollMs?: number;
  /** Findings poll interval. */
  findingsPollMs?: number;
  /** Test hook: the API to call. */
  api?: Pick<typeof apiClient, 'getComputeLatest' | 'getComputeFindings' | 'getComputeNodes'>;
}

export interface ComputeData {
  /** Live rows grouped by `pod_uid`. */
  containersByPodUid: Map<string, ComputeContainer[]>;
  /** The same rows grouped by `<namespace>/<pod_name>` — the join key when a
   *  PodInfo carries no uid (utils/compute `containersForNode`). */
  containersByPodName: Map<string, ComputeContainer[]>;
  nodesByName: Map<string, ComputeNode>;
  findings: ComputeFinding[];
  /** Truncation / history-disabled flags from the findings endpoint. */
  findingsMeta: ComputeFindingsMeta;
  /** Client-side ring buffer of the last 60 pod-level samples per `pod_uid`. */
  history: Map<string, RingBuffer<ComputeSample>>;
  /** False when the broker returned no node rows for the namespace (feature
   *  off, or a broker / controller predating it) or every node reports
   *  `compute_enabled=false`. Consumers render exactly as before then. */
  enabled: boolean;
  /** False once the broker answered 404/501 on a compute endpoint: an older
   *  broker. Both polls stop for this namespace session (they retry on the
   *  next namespace change, which is the only cheap "try again" signal). */
  supported: boolean;
  /** Last transient failure (network, 5xx). Cleared by the next good poll;
   *  polling continues. Never set for `unsupported`. */
  error: string | null;
  /** Bumped every time a poll landed — a cheap dependency for memos over `history`. */
  tick: number;
}

const NO_META: ComputeFindingsMeta = { truncated: false, victimsEvaluated: null, historyDisabled: false };

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * The only live poll on the map (design D8): `GET /compute/latest` every
 * 5 s and `GET /compute/findings` every 15 s for the namespace, paused while
 * the tab is hidden and resumed (with an immediate refresh) when it is shown
 * again. Traffic and syscalls stay on manual refresh in usePodData.
 */
export function useComputeData(namespace: string, opts: UseComputeDataOptions = {}): ComputeData {
  const pollMs = opts.pollMs ?? COMPUTE_POLL_MS;
  const findingsPollMs = opts.findingsPollMs ?? COMPUTE_FINDINGS_POLL_MS;
  const api = opts.api ?? apiClient;

  const [containers, setContainers] = useState<ComputeContainer[]>([]);
  const [nodes, setNodes] = useState<ComputeNode[]>([]);
  const [findings, setFindings] = useState<ComputeFinding[]>([]);
  const [findingsMeta, setFindingsMeta] = useState<ComputeFindingsMeta>(NO_META);
  const [error, setError] = useState<string | null>(null);
  const [supported, setSupported] = useState(true);
  const [tick, setTick] = useState(0);

  // Request generation: bumped on every namespace change. A response whose
  // generation is no longer current (the user switched namespace while it
  // was in flight) is discarded instead of landing on the new namespace.
  const generation = useRef(0);

  // Ring buffers live in a ref and are mutated in place on every poll; the
  // `history` state is a fresh Map over the same buffers per poll so a memo
  // keyed on it re-reads them. Reset on namespace change.
  const historyRef = useRef<Map<string, RingBuffer<ComputeSample>>>(new Map());
  const [history, setHistory] = useState<Map<string, RingBuffer<ComputeSample>>>(() => new Map());
  const inflightLatest = useRef(false);
  const inflightFindings = useRef(false);

  const hidden = () => typeof document !== 'undefined' && document.hidden;

  // One 404 is enough: stop polling and say so once, at debug — an older
  // broker is a supported configuration, not an error to log every 5 s.
  const markUnsupported = useCallback((err: ComputeUnsupportedError) => {
    setSupported((was) => {
      if (was) console.debug(`[compute] ${err.message}; compute polling stopped for this namespace`);
      return false;
    });
  }, []);

  const refreshLatest = useCallback(async () => {
    if (inflightLatest.current) return;
    inflightLatest.current = true;
    const gen = generation.current;
    try {
      const res = await api.getComputeLatest(namespace);
      if (gen !== generation.current) return; // stale: namespace changed while in flight
      const now = Date.now();
      const byUid = new Map<string, ComputeContainer[]>();
      for (const c of res.containers) {
        const list = byUid.get(c.pod_uid);
        if (list) list.push(c);
        else byUid.set(c.pod_uid, [c]);
      }
      const history = historyRef.current;
      byUid.forEach((rows, uid) => {
        let buf = history.get(uid);
        if (!buf) {
          buf = new RingBuffer<ComputeSample>(COMPUTE_HISTORY_SAMPLES);
          history.set(uid, buf);
        }
        buf.push(podLevelSample(rows, now));
      });
      // Drop pods that stopped reporting so a recycled uid never inherits history.
      for (const uid of [...history.keys()]) {
        if (!byUid.has(uid)) history.delete(uid);
      }
      setContainers(res.containers);
      // Namespace-scoped node rows are the live ones; keep any other node we
      // learned from the one-shot /compute/nodes fetch.
      setNodes((prev) => {
        const byName = new Map(prev.map((n) => [n.node, n]));
        for (const n of res.nodes) byName.set(n.node, n);
        return [...byName.values()];
      });
      setHistory(new Map(history));
      setError(null);
      setTick((t) => t + 1);
    } catch (err) {
      if (gen !== generation.current) return;
      if (err instanceof ComputeUnsupportedError) markUnsupported(err);
      else setError(describe(err));
    } finally {
      if (gen === generation.current) inflightLatest.current = false;
    }
  }, [api, namespace, markUnsupported]);

  const refreshFindings = useCallback(async () => {
    if (inflightFindings.current) return;
    inflightFindings.current = true;
    const gen = generation.current;
    try {
      const res = await api.getComputeFindings({ namespace });
      if (gen !== generation.current) return;
      setFindings(res.findings);
      setFindingsMeta({
        truncated: res.truncated === true,
        victimsEvaluated: typeof res.victims_evaluated === 'number' ? res.victims_evaluated : null,
        historyDisabled: res.history_disabled === true,
      });
    } catch (err) {
      if (gen !== generation.current) return;
      if (err instanceof ComputeUnsupportedError) markUnsupported(err);
      else setError(describe(err));
    } finally {
      if (gen === generation.current) inflightFindings.current = false;
    }
  }, [api, namespace, markUnsupported]);

  // Every node's row, once per namespace load, so a pod with no sample yet
  // can still say `off` / `unsupported` / `pending` from its node's state.
  const loadNodes = useCallback(async () => {
    const gen = generation.current;
    try {
      const rows = await api.getComputeNodes();
      if (gen !== generation.current) return;
      setNodes((prev) => {
        const byName = new Map(rows.map((n) => [n.node, n]));
        for (const n of prev) byName.set(n.node, n); // live rows win
        return [...byName.values()];
      });
    } catch (err) {
      if (gen !== generation.current) return;
      if (err instanceof ComputeUnsupportedError) markUnsupported(err);
      // Any other failure here is not worth surfacing: the 5 s poll carries the same rows.
    }
  }, [api, markUnsupported]);

  useEffect(() => {
    generation.current += 1;
    historyRef.current = new Map();
    inflightLatest.current = false;
    inflightFindings.current = false;
    /* eslint-disable react-hooks/set-state-in-effect -- reset-on-namespace, same shape as DataTable's reset-on-pod */
    setContainers([]);
    setNodes([]);
    setFindings([]);
    setFindingsMeta(NO_META);
    setHistory(new Map());
    setError(null);
    setSupported(true);
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [namespace]);

  useEffect(() => {
    if (!supported) return; // an older broker: no timers, no listeners, nothing to clean up
    if (!hidden()) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount, same as useSeccompProfiles
      void loadNodes();
      void refreshLatest();
      void refreshFindings();
    }
    const timers: ReturnType<typeof setInterval>[] = [];
    if (pollMs > 0) timers.push(setInterval(() => { if (!hidden()) void refreshLatest(); }, pollMs));
    if (findingsPollMs > 0) timers.push(setInterval(() => { if (!hidden()) void refreshFindings(); }, findingsPollMs));

    // Coming back to a hidden tab: refresh at once rather than waiting out
    // the interval, so the gauges never show a stale sample after a resume.
    const onVisibility = () => {
      if (!hidden()) {
        void refreshLatest();
        void refreshFindings();
      }
    };
    if (typeof document !== 'undefined') document.addEventListener('visibilitychange', onVisibility);
    return () => {
      timers.forEach(clearInterval);
      if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [refreshLatest, refreshFindings, loadNodes, pollMs, findingsPollMs, supported]);

  const containersByPodUid = useMemo(() => {
    const m = new Map<string, ComputeContainer[]>();
    for (const c of containers) {
      const list = m.get(c.pod_uid);
      if (list) list.push(c);
      else m.set(c.pod_uid, [c]);
    }
    return m;
  }, [containers]);

  const containersByPodName = useMemo(() => {
    const m = new Map<string, ComputeContainer[]>();
    for (const c of containers) {
      const key = podNameKey(c.namespace, c.pod_name);
      const list = m.get(key);
      if (list) list.push(c);
      else m.set(key, [c]);
    }
    return m;
  }, [containers]);

  const nodesByName = useMemo(() => new Map(nodes.map((n) => [n.node, n])), [nodes]);

  const enabled = useMemo(() => supported && nodes.length > 0 && nodes.some((n) => n.compute_enabled), [nodes, supported]);

  return {
    containersByPodUid,
    containersByPodName,
    nodesByName,
    findings,
    findingsMeta,
    history,
    enabled,
    supported,
    error,
    tick,
  };
}
