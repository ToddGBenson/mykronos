/**
 * When does this repository turn no-go on its own? (spec 26 §4)
 *
 * `finding_age` escalates on a date, so a repository with a static backlog
 * crosses a band on a day that is already computable. The difference between
 * a verdict that changes overnight and one somebody saw coming is that
 * somebody said it in advance.
 *
 * Deliberately one sentence and deliberately not a chart. It is a projection
 * of a known curve over known ages — not a model — and it must not acquire
 * the visual authority of one.
 */

import { Label } from "@/components/primitives";

type Forecast = {
  available?: boolean;
  crosses_in_days?: number | null;
  findings_involved?: number;
  reaches?: string;
  reason?: string;
};

export function AgeForecast({ forecast }: { forecast: Forecast | null }) {
  // Nothing to say is said by saying nothing. A panel reading "no forecast
  // available" is a row of furniture on a tab that already has enough.
  if (!forecast?.available || forecast.crosses_in_days == null) {
    return null;
  }

  const days = forecast.crosses_in_days;

  return (
    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border border-high bg-high-wash px-3 py-2">
      <Label>Forecast</Label>
      <p className="max-w-prose text-[11px] leading-relaxed text-ink-2">
        With no changes, this repository reaches{" "}
        <span className="font-mono font-semibold text-critical">
          {(forecast.reaches ?? "no_go").replace(/_/g, " ")}
        </span>{" "}
        in{" "}
        <span className="tabular font-mono font-semibold text-ink">
          {days} day{days === 1 ? "" : "s"}
        </span>{" "}
        as {forecast.findings_involved ?? 1} finding
        {(forecast.findings_involved ?? 1) === 1 ? "" : "s"} cross their age
        threshold.
      </p>
    </div>
  );
}
