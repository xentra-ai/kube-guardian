// Hand-rolled SVG sparkline (design D8: no chart dependency). Draws the
// last N samples as a line with a soft fill, optionally against a capacity
// line so "how close to the limit" reads at a glance.

import { sparklinePath } from '../../utils/sparkline';

export interface SparklineProps {
  /** Oldest → newest. Fewer than two points draws a flat baseline. */
  values: readonly number[];
  /** Fixed y-axis maximum (e.g. the limit); default = max of values. */
  max?: number | null;
  width?: number;
  height?: number;
  /** CSS colour for the stroke; defaults to the accent token. */
  color?: string;
  /** Number of slots the width is divided into (so a short buffer grows from the right). */
  capacity?: number;
  className?: string;
  title?: string;
}

export function Sparkline({
  values,
  max,
  width = 200,
  height = 28,
  color = 'var(--color-hubble-accent)',
  capacity = values.length,
  className = '',
  title,
}: SparklineProps) {
  const dataMax = values.reduce((m, v) => (v > m ? v : m), 0);
  const yMax = max && max > 0 ? Math.max(max, dataMax) : dataMax || 1;
  const path = sparklinePath(values, width, height, yMax, capacity);
  const n = Math.max(capacity, values.length);
  const step = n > 1 ? width / (n - 1) : 0;
  const startX = (n - values.length) * step;
  const capY = max && max > 0 ? height - (Math.min(max, yMax) / yMax) * (height - 1) - 0.5 : null;

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width="100%"
      height={height}
      preserveAspectRatio="none"
      className={className}
      role="img"
      aria-label={title}
      data-testid="sparkline"
    >
      {title && <title>{title}</title>}
      {capY !== null && (
        <line x1={0} x2={width} y1={capY} y2={capY} stroke="var(--theme-border-strong)" strokeDasharray="3 3" strokeWidth={1} />
      )}
      {path && (
        <>
          <path d={`${path} L${width},${height} L${startX.toFixed(1)},${height} Z`} fill={color} fillOpacity={0.12} stroke="none" />
          <path d={path} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
        </>
      )}
    </svg>
  );
}
