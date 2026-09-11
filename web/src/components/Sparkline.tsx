// Sparkline renders a compact 0–100 series as an inline SVG. Values are
// oldest→newest left→right.
export function Sparkline({ values, label }: { values: number[]; label: string }) {
  const w = 220;
  const h = 44;
  const latest = values.length ? values[values.length - 1] : 0;
  let path = "";
  if (values.length > 1) {
    const step = w / (values.length - 1);
    path = values
      .map((v, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)},${(h - (v / 100) * h).toFixed(1)}`)
      .join(" ");
  }
  const color = latest >= 90 ? "var(--danger)" : latest >= 70 ? "var(--warn)" : "var(--accent)";
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span className="who">{label}</span>
        <span className="mono" style={{ fontWeight: 600 }}>
          {latest.toFixed(0)}%
        </span>
      </div>
      <svg width="100%" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ display: "block" }}>
        <line x1="0" y1={h - (70 / 100) * h} x2={w} y2={h - (70 / 100) * h} stroke="var(--border)" strokeWidth="1" />
        {path && <path d={path} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" />}
      </svg>
    </div>
  );
}
