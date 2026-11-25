// Простой SVG-график (без внешних зависимостей): наборы рядов {label, points:[x,y], color}.
type Series = { label: string; points: [number, number][]; color: string };

export default function LineChart({ series, width = 640, height = 220, yMax, yMin = 0 }:
  { series: Series[]; width?: number; height?: number; yMax?: number; yMin?: number }) {
  const pad = 36;
  const xs = series.flatMap((s) => s.points.map((p) => p[0]));
  const ys = series.flatMap((s) => s.points.map((p) => p[1]));
  const x0 = xs.length ? Math.min(...xs) : 0, x1 = xs.length ? Math.max(...xs) : 1;
  const mx = yMax ?? (ys.length ? Math.max(...ys) : 1);
  const sx = (x: number) => pad + (x1 === x0 ? 0 : (x - x0) / (x1 - x0)) * (width - 2 * pad);
  const sy = (y: number) => height - pad - ((y - yMin) / (mx - yMin || 1)) * (height - 2 * pad);
  return (
    <svg width={width} height={height} role="img" aria-label="trend">
      <line x1={pad} y1={height - pad} x2={width - pad} y2={height - pad} stroke="var(--border)" />
      <line x1={pad} y1={pad} x2={pad} y2={height - pad} stroke="var(--border)" />
      <text x={4} y={pad + 4} fill="var(--fg-soft)" fontSize={11}>{mx}</text>
      <text x={4} y={height - pad} fill="var(--fg-soft)" fontSize={11}>{yMin}</text>
      {series.map((s) => (
        <g key={s.label}>
          <polyline fill="none" stroke={s.color} strokeWidth={2}
            points={s.points.map(([x, y]) => `${sx(x)},${sy(y)}`).join(" ")} />
          {s.points.map(([x, y], i) => <circle key={i} cx={sx(x)} cy={sy(y)} r={2.5} fill={s.color} />)}
        </g>))}
      <g>{series.map((s, i) => (<g key={s.label} transform={`translate(${pad + i * 150}, ${height - 12})`}>
        <rect width={10} height={10} fill={s.color} /><text x={14} y={9} fill="var(--fg)" fontSize={11}>{s.label}</text></g>))}</g>
    </svg>);
}
