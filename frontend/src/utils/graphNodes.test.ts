import { describe, expect, test } from 'vitest';
import type { Node } from 'reactflow';
import { UNPLACED, mergeNodeData, placeNodes, pruneNodes } from './graphNodes';

// Fix #1: the 5 s compute poll rebuilds every node object with new gauge
// data. That must repaint the cards and NEVER move them — a card the user
// dragged has to stay where it was dropped until the layout itself changes.

const node = (id: string, data: Record<string, unknown> = {}, selected = false): Node => ({
  id, type: 'podNode', position: { x: 0, y: 0 }, data, selected,
});

describe('placeNodes (a layout result)', () => {
  test('hidden until ELK has placed at least one of the current nodes', () => {
    expect(placeNodes([node('a')], new Map())).toEqual([]);
    expect(placeNodes([], new Map([['a', { x: 1, y: 1 }]]))).toEqual([]);
  });
  test('places every node; an unplaced one is parked off-canvas', () => {
    const out = placeNodes([node('a'), node('b')], new Map([['a', { x: 10, y: 20 }]]));
    expect(out.map((n) => n.position)).toEqual([{ x: 10, y: 20 }, UNPLACED]);
  });
});

describe('pruneNodes (a layout-signature change)', () => {
  test('namespace switch: a wholly new id set blanks the graph until ELK lands', () => {
    const laid = placeNodes([node('payments-api')], new Map([['payments-api', { x: 1, y: 1 }]]));
    expect(pruneNodes(laid, new Set(['batch-etl']))).toEqual([]);
  });
  test('expansion toggle / node added: surviving cards keep their (dragged) positions', () => {
    let laid = placeNodes([node('a'), node('b')], new Map([['a', { x: 1, y: 1 }], ['b', { x: 2, y: 2 }]]));
    laid = laid.map((n) => (n.id === 'a' ? { ...n, position: { x: 99, y: 99 } } : n));
    const pruned = pruneNodes(laid, new Set(['a', 'b', 'c']));
    expect(pruned).toBe(laid);
    expect(pruned[0].position).toEqual({ x: 99, y: 99 });
    expect(pruneNodes(laid, new Set(['a'])).map((n) => n.id)).toEqual(['a']);
  });
});

describe('mergeNodeData (a data tick)', () => {
  test('drag a node, tick 5 s with fresh data: position unchanged, data replaced', () => {
    // Layout lands.
    let nodes = placeNodes([node('a', { cpu: 1 }), node('b', { cpu: 1 })], new Map([['a', { x: 10, y: 20 }], ['b', { x: 300, y: 20 }]]));
    // The user drags card "a" (what React Flow's onNodesChange applies).
    nodes = nodes.map((n) => (n.id === 'a' ? { ...n, position: { x: 555, y: 444 }, dragging: false } : n));
    // 5 s later the compute poll rebuilt every node object with new gauges.
    const tick = [node('a', { cpu: 2 }), node('b', { cpu: 2 })];
    const merged = mergeNodeData(nodes, tick);
    expect(merged.find((n) => n.id === 'a')!.position).toEqual({ x: 555, y: 444 });
    expect(merged.find((n) => n.id === 'b')!.position).toEqual({ x: 300, y: 20 });
    expect(merged.map((n) => n.data)).toEqual([{ cpu: 2 }, { cpu: 2 }]);
  });
  test('selection travels with the tick; identical data returns prev itself', () => {
    const data = { cpu: 1 };
    const laid = placeNodes([node('a', data)], new Map([['a', { x: 1, y: 2 }]]));
    expect(mergeNodeData(laid, [node('a', data)])).toBe(laid);
    const selected = mergeNodeData(laid, [node('a', data, true)]);
    expect(selected).not.toBe(laid);
    expect(selected[0].selected).toBe(true);
    expect(selected[0].position).toEqual({ x: 1, y: 2 });
  });
  test('never adds or removes nodes — that is a layout change, handled by placeNodes', () => {
    const laid = placeNodes([node('a'), node('b')], new Map([['a', { x: 1, y: 1 }], ['b', { x: 2, y: 2 }]]));
    const merged = mergeNodeData(laid, [node('a', { cpu: 9 }), node('c')]);
    expect(merged.map((n) => n.id)).toEqual(['a', 'b']);
    expect(merged[0].data).toEqual({ cpu: 9 });
    expect(mergeNodeData([], [node('a')])).toEqual([]);
  });
});
