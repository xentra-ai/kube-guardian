// Path geometry for the hand-rolled SVG sparkline (components/ui/Sparkline).
// Pure, so the drawing can be asserted without rendering.

/**
 * An SVG path through `values` (oldest → newest), right-aligned inside
 * `capacity` slots so a buffer that is still filling grows from the right.
 * `max` is the y-axis ceiling; values are clamped to [0, max].
 */
export function sparklinePath(values: readonly number[], width: number, height: number, max: number, capacity: number): string {
  if (values.length === 0) return '';
  const n = Math.max(capacity, values.length);
  const step = n > 1 ? width / (n - 1) : 0;
  const offset = (n - values.length) * step;
  const y = (v: number) => {
    const clamped = max > 0 ? Math.min(Math.max(v, 0), max) / max : 0;
    return height - clamped * (height - 1) - 0.5;
  };
  return values
    .map((v, i) => `${i === 0 ? 'M' : 'L'}${(offset + i * step).toFixed(1)},${y(v).toFixed(1)}`)
    .join(' ');
}
