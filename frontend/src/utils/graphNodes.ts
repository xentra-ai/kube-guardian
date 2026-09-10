// React Flow node reconciliation for the map (pure, so it is testable
// without ReactFlow / ELK).
//
// Two different events touch the node list and they must NOT be conflated:
//   - a LAYOUT result (ELK finished for the current node set): every node is
//     placed at its computed position — `placeNodes`;
//   - a DATA tick (the 5 s compute poll rebuilt the node objects, a card was
//     selected, a gauge changed): the existing nodes keep their positions —
//     including one the user just dragged — and only `data` / `selected`
//     are replaced — `mergeNodeData`.
// Conflating the two was the bug where a dragged card snapped back every 5 s.

import type { Node } from 'reactflow';

export type Positions = ReadonlyMap<string, { x: number; y: number }>;

/** Off-canvas parking spot for a node ELK has not placed (never visible). */
export const UNPLACED = { x: -9999, y: -9999 } as const;

/**
 * Nodes for a fresh layout. Returns [] while ELK has placed none of the
 * current set, so the graph stays hidden rather than flashing at (0,0).
 */
export function placeNodes(displayNodes: readonly Node[], positions: Positions): Node[] {
  const hasPositions = displayNodes.length > 0 && displayNodes.some((n) => positions.has(n.id));
  if (!hasPositions) return [];
  return displayNodes.map((node) => ({
    ...node,
    position: positions.get(node.id) ?? { ...UNPLACED },
  }));
}

/**
 * A data tick over an already-laid-out list: same nodes, same positions
 * (dragged or laid out), new `data` / `selected`. Nodes that are not in
 * `prev` are NOT added and nodes missing from `next` are NOT removed here —
 * both change the layout signature and arrive through `placeNodes` once
 * ELK has run. Returns `prev` itself when nothing changed.
 */
export function mergeNodeData(prev: readonly Node[], next: readonly Node[]): Node[] {
  if (prev.length === 0) return prev as Node[];
  const byId = new Map(next.map((n) => [n.id, n]));
  let changed = false;
  const out = prev.map((n) => {
    const fresh = byId.get(n.id);
    if (!fresh || (fresh.data === n.data && (fresh.selected ?? false) === (n.selected ?? false))) return n;
    changed = true;
    return { ...n, data: fresh.data, selected: fresh.selected };
  });
  return changed ? out : (prev as Node[]);
}
