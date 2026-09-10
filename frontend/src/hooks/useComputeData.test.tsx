// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { act, cleanup, renderHook } from '@testing-library/react';
import { useComputeData } from './useComputeData';
import type { ComputeContainer, ComputeFinding, ComputeLatestResponse, ComputeNode } from '../types/compute';

// Contract (design D8 / wire contract): 5 s poll of latest, 15 s poll of
// findings, paused while the tab is hidden, a 60-sample ring buffer per pod
// summing the pod's containers, and `enabled=false` when no node reports.

const node = (over: Partial<ComputeNode> = {}): ComputeNode => ({
  node: 'worker-1', ts: 't', interval_ms: 5000, ctxt_per_sec: 1000,
  compute_enabled: true, compute_supported: true, contention_loaded: false,
  cpu_some10: 0, cpu_full10: 0, mem_some10: 0, mem_full10: 0,
  cpu_cores: 8, memory_bytes: 32 * 1024 ** 3,
  bpf_runq_enqueued: 0, bpf_runq_hist: 0, bpf_pair: 0, unknown_blame_share: 0, updated_at: 't',
  ...over,
});

const container = (over: Partial<ComputeContainer> = {}): ComputeContainer => ({
  container_uid: 'uid-a/app', pod_uid: 'uid-a', namespace: 'payments', pod_name: 'api-1', container: 'app', node: 'worker-1',
  cgroup_id: 1, ts: 't', interval_ms: 5000,
  cpu_usage_millis: 100, cpu_quota_usec: null, cpu_period_usec: 100000, cpu_request_millis: 250, cpu_limit_millis: 500,
  cpu_nr_periods: 50, cpu_nr_throttled: 0, cpu_throttled_usec: 0, cpu_psi_some10: 0, cpu_psi_full10: 0,
  mem_current: 1000, mem_working_set: 800, mem_limit: 4000, mem_request: 2000, mem_psi_some10: 0, mem_psi_full10: 0,
  mem_events_high: 0, mem_events_max: 0, mem_oom_kill: 0, mem_refault: 0, mem_pgmajfault: 0,
  runq_count: null, runq_p50_us: null, runq_p95_us: null, runq_p99_us: null, runq_max_us: null, runq_overflow: null,
  blame: null, updated_at: 't',
  ...over,
});

function fakeApi(latest: () => ComputeLatestResponse, findings: () => ComputeFinding[] = () => []) {
  return {
    getComputeLatest: vi.fn(async () => latest()),
    getComputeFindings: vi.fn(async () => findings()),
  };
}

const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

let hiddenValue = false;

beforeEach(() => {
  vi.useFakeTimers();
  hiddenValue = false;
  Object.defineProperty(document, 'hidden', { configurable: true, get: () => hiddenValue });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('useComputeData', () => {
  test('polls latest every 5 s and findings every 15 s', async () => {
    const api = fakeApi(() => ({ containers: [container()], nodes: [node()] }));
    renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(api.getComputeLatest).toHaveBeenCalledTimes(1);
    expect(api.getComputeLatest).toHaveBeenCalledWith('payments');
    expect(api.getComputeFindings).toHaveBeenCalledTimes(1);
    expect(api.getComputeFindings).toHaveBeenCalledWith({ namespace: 'payments' });

    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(api.getComputeLatest).toHaveBeenCalledTimes(2);
    expect(api.getComputeFindings).toHaveBeenCalledTimes(1);

    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(api.getComputeLatest).toHaveBeenCalledTimes(4);
    expect(api.getComputeFindings).toHaveBeenCalledTimes(2);
  });

  test('pauses while the document is hidden and refreshes at once when shown again', async () => {
    const api = fakeApi(() => ({ containers: [container()], nodes: [node()] }));
    renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(api.getComputeLatest).toHaveBeenCalledTimes(1);

    hiddenValue = true;
    await act(async () => { await vi.advanceTimersByTimeAsync(20_000); });
    expect(api.getComputeLatest).toHaveBeenCalledTimes(1);
    expect(api.getComputeFindings).toHaveBeenCalledTimes(1);

    hiddenValue = false;
    await act(async () => { document.dispatchEvent(new Event('visibilitychange')); });
    await flush();
    expect(api.getComputeLatest).toHaveBeenCalledTimes(2);
    expect(api.getComputeFindings).toHaveBeenCalledTimes(2);
  });

  test('keeps a 60-sample ring buffer per pod, summing the pod containers', async () => {
    let cpu = 0;
    const api = fakeApi(() => {
      cpu += 10;
      return {
        containers: [
          container({ container_uid: 'uid-a/app', cpu_usage_millis: cpu, mem_working_set: 100 }),
          container({ container_uid: 'uid-a/sidecar', container: 'sidecar', cpu_usage_millis: 5, mem_working_set: 50 }),
        ],
        nodes: [node()],
      };
    });
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.enabled).toBe(true);
    expect(result.current.containersByPodUid.get('uid-a')).toHaveLength(2);
    expect(result.current.containersByPodName.get('payments/api-1')).toHaveLength(2);
    const first = result.current.history.get('uid-a')!.values();
    expect(first).toHaveLength(1);
    expect(first[0]).toMatchObject({ cpuMillis: 15, workingSetBytes: 150 });

    // 70 more polls → the buffer holds the last 60 only, oldest first.
    for (let i = 0; i < 70; i++) {
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    }
    const samples = result.current.history.get('uid-a')!.values();
    expect(samples).toHaveLength(60);
    expect(samples[59].cpuMillis).toBe(cpu + 5);
    expect(samples[0].cpuMillis).toBe(cpu + 5 - 59 * 10);
  });

  test('drops the history of a pod that stopped reporting', async () => {
    let gone = false;
    const api = fakeApi(() => ({ containers: gone ? [] : [container()], nodes: [node()] }));
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.history.has('uid-a')).toBe(true);
    gone = true;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(result.current.history.has('uid-a')).toBe(false);
  });

  test('enabled=false when there are no node rows', async () => {
    const api = fakeApi(() => ({ containers: [], nodes: [] }));
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.enabled).toBe(false);
  });

  test('enabled=false when every node reports compute_enabled=false', async () => {
    const api = fakeApi(() => ({ containers: [], nodes: [node({ compute_enabled: false }), node({ node: 'worker-2', compute_enabled: false })] }));
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.enabled).toBe(false);
  });

  test('enabled=true when at least one node has compute on', async () => {
    const api = fakeApi(() => ({ containers: [], nodes: [node({ compute_enabled: false }), node({ node: 'worker-2' })] }));
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    expect(result.current.enabled).toBe(true);
  });

  test('a namespace change resets rows and history and refetches', async () => {
    const api = fakeApi(() => ({ containers: [container()], nodes: [node()] }));
    const { result, rerender } = renderHook(({ ns }) => useComputeData(ns, { api }), { initialProps: { ns: 'payments' } });
    await flush();
    expect(result.current.history.size).toBe(1);
    rerender({ ns: 'batch' });
    await flush();
    expect(api.getComputeLatest).toHaveBeenLastCalledWith('batch');
    expect(api.getComputeFindings).toHaveBeenLastCalledWith({ namespace: 'batch' });
    // The fresh namespace's first poll starts a new buffer (1 sample, not 2).
    expect(result.current.history.get('uid-a')!.length).toBe(1);
  });

  test('surfaces an API error without dropping the last good data', async () => {
    let fail = false;
    const api = {
      getComputeLatest: vi.fn(async () => {
        if (fail) throw new Error('boom');
        return { containers: [container()], nodes: [node()] };
      }),
      getComputeFindings: vi.fn(async () => []),
    };
    const { result } = renderHook(() => useComputeData('payments', { api }));
    await flush();
    fail = true;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(result.current.error).toBe('boom');
    expect(result.current.containersByPodUid.size).toBe(1);
  });
});
