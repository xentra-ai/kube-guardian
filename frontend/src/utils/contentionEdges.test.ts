import { describe, expect, test } from 'vitest';
import { blameShareLabel, buildContentionEdges, contentionEdgeId, externalCulpritId } from './contentionEdges';
import type { PodInfo, PodNodeData } from '../types';
import type { ComputeFinding } from '../types/compute';

// Contention edges (design D8): culprit → victim, id per the wire contract,
// culprits outside the namespace drawn as external nodes the way
// cross-namespace traffic peers are — reusing the peer's node when it has one.

const pod = (name: string, ns: string, extra: Partial<PodInfo> = {}): PodInfo => ({
  pod_name: name, pod_ip: '10.0.0.1', pod_namespace: ns, time_stamp: 't', node_name: 'worker-1', is_dead: false, ...extra,
});
const local = (id: string, p: PodInfo): PodNodeData => ({ id, label: id, pod: p, pods: [p], traffic: [], isExpanded: false });
const finding = (over: Partial<ComputeFinding> = {}, culprit: Partial<NonNullable<ComputeFinding['culprit']>> = {}): ComputeFinding => ({
  kind: 'noisy-neighbor', severity: 'high',
  victim: { pod_uid: 'uid-api', namespace: 'payments', pod_name: 'api-1', container: 'app', container_uid: 'uid-api/app', node: 'worker-1' },
  culprit: { kind: 'pod', ref: 'batch/etl-1/worker', pod_uid: 'uid-etl', namespace: 'batch', pod_name: 'etl-1', container_uid: 'uid-etl/worker', blame_share: 0.71, cpu_usage_millis: 1900, cpu_request_millis: 500, ...culprit },
  evidence: { window_minutes: 5, cpu_psi_some10_max: 31, cpu_psi_full10_max: 0, runq_p99_us_max: 48000, throttled_ratio: 0.02, mem_psi_some10_max: 0, node_mem_some10_max: 0, refault_delta: 0, mem_events_high_delta: 0 },
  first_seen: 't', last_seen: 't', message: 'starved',
  ...over,
});

describe('buildContentionEdges', () => {
  const victim = local('payments-api', pod('api-1', 'payments', { pod_obj: { metadata: { uid: 'uid-api' } } }));

  test('cross-namespace culprit with no traffic node → synthetic external node + edge', () => {
    const { edges, externalCulprits } = buildContentionEdges([finding()], [victim], [], [pod('etl-1', 'batch', { pod_identity: 'etl' })]);
    expect(edges).toHaveLength(1);
    expect(edges[0].id).toBe(contentionEdgeId('uid-etl', 'uid-api'));
    expect(edges[0].id).toBe('contention:uid-etl->uid-api');
    expect(edges[0].target).toBe('payments-api');
    expect(edges[0].source).toBe(externalCulpritId('batch', 'etl'));
    expect(edges[0].blameShare).toBe(0.71);
    expect(externalCulprits).toHaveLength(1);
    expect(externalCulprits[0]).toMatchObject({ id: 'external-batch-etl-in', isExternal: true, externalNamespace: 'batch', label: 'etl' });
  });

  test('culprit that already is a traffic peer reuses that node', () => {
    const peer: PodNodeData = { ...local('external-batch-etl-in', pod('etl-1', 'batch')), isExternal: true, externalNamespace: 'batch' };
    const { edges, externalCulprits } = buildContentionEdges([finding()], [victim], [peer], []);
    expect(edges[0].source).toBe('external-batch-etl-in');
    expect(externalCulprits).toHaveLength(0);
  });

  test('in-namespace culprit (same-namespace neighbour) → local → local edge, no external node', () => {
    const culprit = local('payments-worker', pod('worker-1', 'payments', { pod_obj: { metadata: { uid: 'uid-w' } } }));
    const f = finding({}, { pod_uid: 'uid-w', namespace: 'payments', pod_name: 'worker-1' });
    const { edges, externalCulprits } = buildContentionEdges([f], [victim, culprit], [], []);
    expect(edges[0]).toMatchObject({ source: 'payments-worker', target: 'payments-api' });
    expect(externalCulprits).toHaveLength(0);
  });

  test('victim matched by ns/name when the record carries no uid', () => {
    const noUid = local('payments-api', pod('api-1', 'payments'));
    const { edges } = buildContentionEdges([finding()], [noUid], [], []);
    expect(edges).toHaveLength(1);
  });

  test('skips non-pod culprits, non-noisy-neighbour kinds, unknown victims and self-edges; de-duplicates', () => {
    const system = finding({}, { kind: 'system', ref: 'system.slice/kubelet.service', pod_uid: null, namespace: null, pod_name: null });
    const throttled = finding({ kind: 'cpu-throttled', culprit: null });
    const missing = finding({ victim: { ...finding().victim, pod_uid: 'uid-x', pod_name: 'nope' } });
    const self = finding({}, { pod_uid: 'uid-api', namespace: 'payments', pod_name: 'api-1' });
    const { edges } = buildContentionEdges([system, throttled, missing, self, finding(), finding()], [victim], [], []);
    expect(edges).toHaveLength(1);
  });

  test('label rounds the share to a percent', () => {
    expect(blameShareLabel(0.714)).toBe('71% of wait');
  });
});
