import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { apiClient } from '../services/api';
import type { ComputeContainer, ComputeFinding, ComputeNode, ComputeSample } from '../types/compute';
import { COMPUTE_HISTORY_SAMPLES, RingBuffer, podLevelSample, podNameKey } from '../utils/compute';

export const COMPUTE_POLL_MS = 5_000;
export const COMPUTE_FINDINGS_POLL_MS = 15_000;

export interface UseComputeDataOptions {
  /** Latest-rows poll interval; ≤ 0 disables polling (fetch once). */
  pollMs?: number;
  /** Findings poll interval. */
  findingsPollMs?: number;
  /** Test hook: the API to call. */
  api?: Pick<typeof apiClient, 'getComputeLatest' | 'getComputeFindings'>;
}

export interface ComputeData {
  /** Live rows grouped by `pod_uid`. */
  containersByPodUid: Map<string, ComputeContainer[]>;
  /** The same rows grouped by `<namespace>/<pod_name>` — the join key when a
   *  PodInfo carries no uid (utils/compute `containersForNode`). */
  containersByPodName: Map<string, ComputeContainer[]>;
  nodesByName: Map<string, ComputeNode>;
  findings: ComputeFinding[];
  /** Client-side ring buffer of the last 60 pod-level samples per `pod_uid`. */
  history: Map<string, RingBuffer<ComputeSample>>;
  /** False when the broker returned no node rows for the namespace (feature
   *  off, or a broker / controller predating it) or every node reports
   *  `compute_enabled=false`. Consumers render exactly as before then. */
  enabled: boolean;
  error: string | null;
  /** Bumped every time a poll landed — a cheap dependency for memos over `history`. */
  tick: number;
}

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
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  // Ring buffers live in a ref and are mutated in place on every poll; the
  // `history` state is a fresh Map over the same buffers per poll so a memo
  // keyed on it re-reads them. Reset on namespace change.
  const historyRef = useRef<Map<string, RingBuffer<ComputeSample>>>(new Map());
  const [history, setHistory] = useState<Map<string, RingBuffer<ComputeSample>>>(() => new Map());
  const inflightLatest = useRef(false);
  const inflightFindings = useRef(false);

  const hidden = () => typeof document !== 'undefined' && document.hidden;

  const refreshLatest = useCallback(async () => {
    if (inflightLatest.current) return;
    inflightLatest.current = true;
    try {
      const res = await api.getComputeLatest(namespace);
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
      setNodes(res.nodes);
      setHistory(new Map(history));
      setError(null);
      setTick((t) => t + 1);
    } catch (err) {
      setError(describe(err));
    } finally {
      inflightLatest.current = false;
    }
  }, [api, namespace]);

  const refreshFindings = useCallback(async () => {
    if (inflightFindings.current) return;
    inflightFindings.current = true;
    try {
      setFindings(await api.getComputeFindings({ namespace }));
    } catch (err) {
      setError(describe(err));
    } finally {
      inflightFindings.current = false;
    }
  }, [api, namespace]);

  useEffect(() => {
    historyRef.current = new Map();
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch-on-mount, same as useSeccompProfiles
    setContainers([]);
    setNodes([]);
    setFindings([]);
    setHistory(new Map());
    if (!hidden()) {
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
  }, [refreshLatest, refreshFindings, pollMs, findingsPollMs]);

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

  const enabled = useMemo(() => nodes.length > 0 && nodes.some((n) => n.compute_enabled), [nodes]);

  return {
    containersByPodUid,
    containersByPodName,
    nodesByName,
    findings,
    history,
    enabled,
    error,
    tick,
  };
}
