import {
  EmptyState,
  ErrorPanel,
  Label,
  Pill,
  RelativeTime,
  StatTile,
} from "@/components/primitives";
import { PromoteButton } from "@/components/promote-button";
import type { LearningRow, PromotionCandidate } from "@/lib/api";
import { getRetro, getTrend } from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * What the platform has learned, and forgotten (spec 10 §2.4, spec 11 §7).
 *
 * The only view whose subject is the platform's own judgement rather than the
 * code it scans. Two things it deliberately does *not* do: it does not
 * celebrate volume — a hundred dismissals with no reasons is worse than five
 * with them — and it does not draw a trend line before there is enough data
 * to draw one.
 */
export default async function RetroPage({
  searchParams,
}: {
  searchParams: Promise<{ days?: string }>;
}) {
  const params = await searchParams;
  const periodDays = Number(params.days) || 14;
  const [retro, trend] = await Promise.all([getRetro(periodDays), getTrend()]);

  if (!retro.ok && "error" in retro) {
    return <ErrorPanel title="Retro unavailable" detail={retro.error} />;
  }
  if (!retro.ok) return null;

  const report = retro.data;
  const reasoned =
    report.new_entries.length + report.reconfirmed.length - report.unreasoned;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Retro</h1>
        <span className="font-mono text-[11px] text-ink-3">
          {new Date(report.period_start).toISOString().slice(0, 10)} to{" "}
          {new Date(report.period_end).toISOString().slice(0, 10)}
        </span>
        <span className="ml-auto flex gap-1.5">
          {[7, 14, 30, 90].map((days) => (
            <a
              key={days}
              href={`/retro?days=${days}`}
              className={`border px-1.5 py-0.5 font-mono text-[9px] ${
                periodDays === days
                  ? "border-accent bg-accent-wash text-accent"
                  : "border-rule text-ink-3 hover:border-accent"
              }`}
            >
              {days}d
            </a>
          ))}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <StatTile label="New learnings" value={report.new_entries.length} />
        <StatTile label="Reconfirmed" value={report.reconfirmed.length} />
        <StatTile
          label="Fading"
          value={report.decaying.length}
          sub="no longer influencing anything"
        />
        <StatTile
          label="Without a reason"
          value={report.unreasoned}
          sub={reasoned >= 0 ? "cannot dampen or promote" : ""}
          alert={report.unreasoned > 0}
        />
      </div>

      {report.quiet ? (
        <EmptyState
          title="Nothing was learned this period"
          detail={
            <>
              No findings dismissed, no decisions overridden, no notes written.
              Worth a moment rather than a shrug: it means either the tools
              produced nothing worth arguing with, or nobody had time to argue
              with them.
            </>
          }
        />
      ) : null}

      {report.promotion_candidates.length > 0 ? (
        <section className="flex flex-col gap-2">
          <div>
            <h2 className="text-sm font-bold">Ready to generalise</h2>
            <p className="mt-0.5 max-w-prose text-[11px] leading-relaxed text-ink-3">
              Confirmed independently across repositories. Repeated dismissal
              inside one repository is one team&rsquo;s opinion held firmly,
              which is not the same evidence. Nothing below has been applied —
              promotion is a human decision, and changing the Oracle policy is
              a pull request.
            </p>
          </div>
          <ul className="flex flex-col gap-2">
            {report.promotion_candidates.map((candidate) => (
              <CandidateCard key={candidate.subject} candidate={candidate} />
            ))}
          </ul>
        </section>
      ) : null}

      <LearningSection
        title="New this period"
        rows={report.new_entries}
        empty="Nothing new was recorded."
      />
      <LearningSection
        title="Reconfirmed"
        rows={report.reconfirmed}
        empty="Nothing previously known came up again."
        note="Seen again and handled the same way, which resets their decay and raises confidence."
      />
      <LearningSection
        title="Fading"
        rows={report.decaying}
        empty="Nothing has decayed out of use."
        note="Not reconfirmed for long enough that they no longer influence anything. Either the problem went away, or people stopped reporting it — worth asking which."
      />

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-bold">Trend</h2>
        {trend.ok ? (
          <TrendTable report={trend.data} />
        ) : "notEnoughHistory" in trend ? (
          <p className="max-w-prose border border-dashed border-rule bg-paper-2 px-3 py-2 text-[11px] leading-relaxed text-ink-3">
            {trend.notEnoughHistory}
          </p>
        ) : (
          <ErrorPanel title="Trend unavailable" detail={trend.error} />
        )}
      </section>

      <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
        <Label>Reading this page</Label>
        <br />
        Every figure is recomputed from the Knowledge Store and this
        period&rsquo;s dates, so any past report can be re-derived rather than
        trusted. A dismissal with no written reason is kept but cannot raise
        confidence, be promoted, or dampen a rule — the effort was spent
        without teaching the platform anything.
      </p>
    </div>
  );
}

function LearningSection({
  title,
  rows,
  empty,
  note,
}: {
  title: string;
  rows: LearningRow[];
  empty: string;
  note?: string;
}) {
  return (
    <section className="flex flex-col gap-1.5">
      <div>
        <h2 className="text-sm font-bold">
          {title}{" "}
          <span className="font-mono text-[11px] font-normal text-ink-3">
            {rows.length}
          </span>
        </h2>
        {note ? (
          <p className="mt-0.5 max-w-prose text-[11px] leading-relaxed text-ink-3">
            {note}
          </p>
        ) : null}
      </div>

      {rows.length === 0 ? (
        <p className="text-[11px] text-ink-3">{empty}</p>
      ) : (
        <ul className="flex flex-col gap-1.5">
          {rows.map((row) => (
            <li
              key={row.entry_id}
              className="border border-rule bg-paper-2 px-3 py-2"
            >
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="font-mono text-[11px] font-bold">
                  {row.subject}
                </span>
                <ConfidenceBar value={row.confidence} />
                <span className="font-mono text-[10px] text-ink-3">
                  {row.observations} observation{row.observations === 1 ? "" : "s"}
                </span>
                {row.repo_full_name ? (
                  <span className="font-mono text-[10px] text-ink-3">
                    {row.repo_full_name}
                  </span>
                ) : null}
                <span className="ml-auto whitespace-nowrap font-mono text-[10px] text-ink-3">
                  <RelativeTime value={row.last_confirmed_at} />
                </span>
              </div>
              <p className="mt-1 max-w-prose text-[11px] leading-relaxed text-ink-2">
                {row.text}
              </p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function CandidateCard({ candidate }: { candidate: PromotionCandidate }) {
  return (
    <li className="border border-accent bg-accent-wash px-3 py-2">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="font-mono text-[11px] font-bold">{candidate.subject}</span>
        <Pill tone="accent">
          {candidate.from_tier} → {candidate.to_tier}
        </Pill>
        <span className="font-mono text-[10px] text-ink-3">
          {candidate.project_count} repositories · {candidate.total_observations}{" "}
          observations · confidence {candidate.mean_confidence.toFixed(2)}
        </span>
      </div>
      <p className="mt-1 font-mono text-[10px] text-ink-3">
        {candidate.repos.join(", ")}
      </p>
      {candidate.reasons.length > 0 ? (
        <ul className="mt-1.5 flex flex-col gap-0.5">
          {candidate.reasons.slice(0, 3).map((reason) => (
            <li key={reason} className="max-w-prose text-[11px] text-ink-2">
              — {reason}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-1.5 max-w-prose text-[11px] text-ink-3">
          No reason may be shown: the contributing entries are marked
          restricted. Weigh this on the recurrence alone, or ask the
          repositories involved.
        </p>
      )}
      <div className="mt-2">
        <PromoteButton
          subject={candidate.subject}
          sourceType={candidate.source_type}
          toTier={candidate.to_tier}
        />
      </div>
    </li>
  );
}

/** Higher is more believed. Paired with the number, since a bar alone at this
 *  size is hard to read precisely and the exact figure matters here. */
function ConfidenceBar({ value }: { value: number }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className="relative inline-block h-2 w-16 border border-rule bg-paper"
        role="img"
        aria-label={`Confidence ${value.toFixed(2)} of 1`}
      >
        <span
          className={`absolute inset-y-0 left-0 ${
            value >= 0.7 ? "bg-pass" : value >= 0.3 ? "bg-medium" : "bg-rule"
          }`}
          style={{ width: `${Math.min(100, Math.max(0, value * 100))}%` }}
        />
      </span>
      <span className="tabular font-mono text-[10px] text-ink-3">
        {value.toFixed(2)}
      </span>
    </span>
  );
}

function TrendTable({
  report,
}: {
  report: { direction: string; period_days: number; points: {
    period_start: string;
    new_entries: number;
    reconfirmations: number;
    with_reasons: number;
    dismissals: number;
    overrides: number;
  }[] };
}) {
  return (
    <>
      <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
        Learning volume across {report.points.length} periods of{" "}
        {report.period_days} days —{" "}
        <span className="font-mono text-ink-2">{report.direction}</span>. A word
        rather than a slope: a slope on this many points invites more precision
        than they can carry.
      </p>
      <div className="scroll-x border border-rule">
        <table className="w-full min-w-[520px] border-collapse bg-paper-2 font-mono text-[11px]">
          <thead>
            <tr className="border-b-2 border-ink-2 text-left">
              {["Period from", "New", "With reasons", "Reconfirmed", "Dismissals", "Overrides"].map(
                (heading) => (
                  <th
                    key={heading}
                    className="whitespace-nowrap px-2 py-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-ink-3"
                  >
                    {heading}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {report.points.map((point) => (
              <tr
                key={point.period_start}
                className="border-b border-rule-soft last:border-b-0"
              >
                <td className="px-2 py-2 text-ink-2">
                  {new Date(point.period_start).toISOString().slice(0, 10)}
                </td>
                <td className="tabular px-2 py-2">{point.new_entries}</td>
                <td
                  className={`tabular px-2 py-2 ${
                    point.with_reasons < point.new_entries ? "text-high" : ""
                  }`}
                >
                  {point.with_reasons}
                </td>
                <td className="tabular px-2 py-2 text-ink-3">
                  {point.reconfirmations}
                </td>
                <td className="tabular px-2 py-2 text-ink-3">{point.dismissals}</td>
                <td className="tabular px-2 py-2 text-ink-3">{point.overrides}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
