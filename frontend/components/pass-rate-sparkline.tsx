/**
 * One test lane's pass rate over time (spec 19 §1.1).
 *
 * Same shape as `sscs.tsx`'s trust sparkline, and for the same reason: a
 * current-rate box says "70%" and cannot say whether that is 70% recovering
 * from 40% or 70% sliding from 95%. Windows with no runs are dropped rather
 * than plotted at zero — a lane nobody ran and a lane that failed every run
 * are different facts, and plotting both at the floor would say they are
 * the same.
 */

import type { ScanRunTrendPoint } from "@/lib/api";

export function PassRateSparkline({
  capability,
  points,
}: {
  capability: string;
  points: ScanRunTrendPoint[];
}) {
  const scored = points.filter(
    (point): point is ScanRunTrendPoint & { success_rate: number } =>
      point.success_rate != null,
  );
  const empty = points.length - scored.length;

  if (scored.length < 2) {
    return (
      <p className="font-mono text-[9px] text-ink-3">
        {scored.length === 0
          ? "No runs in this window."
          : "One run window so far. A trend needs at least two."}
      </p>
    );
  }

  const width = 420;
  const height = 40;
  const step = width / (scored.length - 1);
  const path = scored
    .map((point, index) => {
      const x = index * step;
      const y = height - Math.max(0, Math.min(1, point.success_rate)) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  const last = scored[scored.length - 1];
  const lastY = height - last.success_rate * height;
  const tone =
    last.success_rate < 0.7
      ? "text-critical"
      : last.success_rate < 0.9
        ? "text-high"
        : "text-pass";

  return (
    <div className="scroll-x">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-10 w-full min-w-[280px] max-w-[420px] border border-rule bg-paper-2"
        role="img"
        aria-label={`${capability} pass rate across ${scored.length} windows, currently ${Math.round(last.success_rate * 100)}%`}
      >
        {/* 90% — the same threshold the scan-health box already colours
            green at, so the line and the box agree about what "good" is. */}
        <line
          x1="0"
          y1={height * 0.1}
          x2={width}
          y2={height * 0.1}
          stroke="currentColor"
          strokeWidth="0.5"
          className="text-rule"
          strokeDasharray="3 3"
        />
        <polyline
          points={path}
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          className={tone}
        />
        <circle cx={width} cy={lastY} r="2.5" className={`fill-current ${tone}`} />
      </svg>
      <p className="mt-1 font-mono text-[9px] text-ink-3">
        {scored.length} window{scored.length === 1 ? "" : "s"} with runs · dashed line is 90%
        {empty > 0 ? ` · ${empty} window${empty === 1 ? "" : "s"} had no runs, omitted` : ""}
      </p>
    </div>
  );
}
