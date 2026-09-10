// Contention (culprit → victim) edges for the map, from noisy-neighbour
// findings (design D8). Pure so NetworkGraph's wiring stays testable
// without React Flow / ELK.

import type { PodInfo, PodNodeData } from '../types';
import type { ComputeFinding } from '../types/compute';
import { podUid } from './peerResolution';
import { podNameKey } from './compute';
import { EDGE_COLOR_DENIED } from './daemonSetPeers';

/** `data` of a React Flow edge of type `contention` (components/ContentionEdge). */
export interface ContentionEdgeData {
  /** 0..1, the culprit's share of the victim's run-queue wait. */
  blameShare: number;
  finding: ComputeFinding;
}

/** Contention shares the Denied red: both mean "something is being starved". */
export const EDGE_COLOR_CONTENTION = EDGE_COLOR_DENIED;

/** `contention:<culpritPodUid>-><victimPodUid>` (the wire contract's edge id). */
export const contentionEdgeId = (culpritPodUid: string, victimPodUid: string): string =>
  `contention:${culpritPodUid}->${victimPodUid}`;

export const blameShareLabel = (share: number): string => `${Math.round(share * 100)}% of wait`;

export interface ContentionEdgeSpec {
  id: string;
  /** Node id of the culprit (in-namespace node, an existing external peer, or a synthetic one). */
  source: string;
  /** Node id of the victim (always an in-namespace node). */
  target: string;
  blameShare: number;
  finding: ComputeFinding;
}

export interface ContentionBuild {
  edges: ContentionEdgeSpec[];
  /** Culprits outside the namespace that no existing node stands for. */
  externalCulprits: PodNodeData[];
}

/** A culprit node id for a pod outside the selected namespace (`-in`: it is a source). */
export const externalCulpritId = (namespace: string, identity: string): string => `external-${namespace}-${identity}-in`;

/**
 * Turns the `noisy-neighbor` findings whose culprit is a pod into edges.
 * The victim must be an in-namespace node (findings are namespace-scoped, so
 * it always is once the pod has loaded). The culprit is matched to an
 * in-namespace node by uid or name, else to an existing external peer
 * node (a cross-namespace traffic peer), else a synthetic external node is
 * produced the way cross-namespace traffic peers are drawn. Edges whose
 * victim is not on the map are skipped.
 */
export function buildContentionEdges(
  findings: readonly ComputeFinding[],
  localPods: readonly PodNodeData[],
  externalNodes: readonly PodNodeData[],
  allPodsLookup: readonly PodInfo[],
): ContentionBuild {
  const localByKey = new Map<string, PodNodeData>();
  for (const node of localPods) {
    const members = node.pods && node.pods.length > 0 ? node.pods : [node.pod];
    for (const m of members) {
      const uid = podUid(m);
      if (uid) localByKey.set(`uid:${uid}`, node);
      localByKey.set(`name:${podNameKey(m.pod_namespace, m.pod_name)}`, node);
    }
  }
  // Existing external peers, by member pod name — a culprit that already is
  // a traffic peer of the namespace gets its edge on the node it already has.
  const externalByName = new Map<string, PodNodeData>();
  for (const node of externalNodes) {
    if (!node.id.endsWith('-in')) continue; // a culprit is a source; the -in node is on the left
    const members = node.pods && node.pods.length > 0 ? node.pods : [node.pod];
    for (const m of members) externalByName.set(`name:${podNameKey(m.pod_namespace, m.pod_name)}`, node);
  }
  const podInfoByName = new Map<string, PodInfo>();
  for (const p of allPodsLookup) podInfoByName.set(podNameKey(p.pod_namespace, p.pod_name), p);

  const edges: ContentionEdgeSpec[] = [];
  const synthetic = new Map<string, PodNodeData>();
  const seen = new Set<string>();

  for (const f of findings) {
    if (f.kind !== 'noisy-neighbor' || !f.culprit || f.culprit.kind !== 'pod' || !f.culprit.pod_name) continue;
    const victim =
      localByKey.get(`uid:${f.victim.pod_uid}`) ?? localByKey.get(`name:${podNameKey(f.victim.namespace, f.victim.pod_name)}`);
    if (!victim) continue;

    const culpritNs = f.culprit.namespace ?? 'unknown'; // null never happens for kind=pod; keep the id well-formed if it does
    const culpritNameKey = `name:${podNameKey(f.culprit.namespace, f.culprit.pod_name)}`;
    let source: PodNodeData | undefined =
      (f.culprit.pod_uid ? localByKey.get(`uid:${f.culprit.pod_uid}`) : undefined) ?? localByKey.get(culpritNameKey) ?? externalByName.get(culpritNameKey);
    if (!source) {
      const known = podInfoByName.get(podNameKey(f.culprit.namespace, f.culprit.pod_name));
      const identity = known?.pod_identity || known?.workload_name || f.culprit.pod_name;
      const id = externalCulpritId(culpritNs, identity);
      source = synthetic.get(id);
      if (!source) {
        const pod: PodInfo = known ?? {
          pod_name: f.culprit.pod_name,
          pod_ip: '',
          pod_namespace: f.culprit.namespace,
          time_stamp: f.last_seen,
          node_name: f.victim.node,
          is_dead: false,
        };
        source = {
          id,
          label: identity,
          pod,
          pods: [pod],
          traffic: [],
          isExpanded: false,
          isExternal: true,
          externalNamespace: culpritNs,
          tooltip: `${culpritNs}/${f.culprit.pod_name} — named as a noisy neighbour of ${f.victim.namespace}/${f.victim.pod_name}`,
        };
        synthetic.set(id, source);
      }
    }
    if (source.id === victim.id) continue;

    const culpritUid = f.culprit.pod_uid ?? `${culpritNs}/${f.culprit.pod_name}`;
    const id = contentionEdgeId(culpritUid, f.victim.pod_uid);
    if (seen.has(id)) continue;
    seen.add(id);
    edges.push({ id, source: source.id, target: victim.id, blameShare: f.culprit.blame_share, finding: f });
  }

  return { edges, externalCulprits: [...synthetic.values()] };
}
