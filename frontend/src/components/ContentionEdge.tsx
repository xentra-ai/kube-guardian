import { BaseEdge, EdgeLabelRenderer, getBezierPath, type EdgeProps } from 'reactflow';
import { EDGE_COLOR_CONTENTION, edgeShareLabel, type ContentionEdgeData } from '../utils/contentionEdges';

// The culprit → victim edge behind a noisy-neighbour finding (design D8):
// dashed, error-coloured, labelled with the culprit's share of the victim's
// wait. It shares the Denied red on purpose — both mean "something is being
// starved" — and is dashed so it never reads as a traffic flow.

export default function ContentionEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  markerEnd,
}: EdgeProps<ContentionEdgeData>) {
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  const share = data?.blameShare ?? 0;
  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={{ stroke: EDGE_COLOR_CONTENTION, strokeWidth: 2, strokeDasharray: '6 4' }}
      />
      <EdgeLabelRenderer>
        <div
          className="nodrag nopan pointer-events-auto absolute rounded-full border border-hubble-error/40 bg-hubble-card px-2 py-0.5 text-[10px] font-mono font-semibold text-hubble-error"
          style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
          title={data?.finding.message}
          data-testid="contention-edge-label"
        >
          {edgeShareLabel(share)}
        </div>
      </EdgeLabelRenderer>
    </>
  );
}
