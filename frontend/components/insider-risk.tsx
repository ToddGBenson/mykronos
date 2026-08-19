/**
 * Insider-risk assessments for one repository.
 *
 * Read spec 06 §9 before changing this. Every other tab in the dashboard shows
 * findings about code; this one shows an assessment of a colleague's pull
 * request, and the presentation is part of the governance rather than a wrapper
 * around it.
 *
 * Three deliberate choices:
 *
 * - The pull request is the subject of every row. The author is a *field* of
 *   the assessment, not its heading — the same data arranged the other way
 *   would read as a per-person file.
 * - Nothing here aggregates. No average score, no worst-contributor list, no
 *   trend per author. Those views are what spec 06 §9 forbids, and the
 *   reliable way not to ship them is not to build the components.
 * - The governance note and the retention statement are on the page, not in a
 *   footnote. Anyone who finds this tab should learn what it is not.
 */

import {
  EmptyState,
  Label,
  Pill,
  RelativeTime,
  ScoreMeter,
} from "@/components/primitives";
import type { InsiderRiskSignal, SignalBreakdown } from "@/lib/api";

const RECOMMENDATION_TONE: Record<string, "critical" | "warn" | "pass" | "muted"> = {
  block_recommended: "critical",
  review_recommended: "warn",
  pass: "pass",
};

/**
 * Every key `aegis.py`'s `SIGNAL_CAP` can emit (spec 20 §3.1). The four
 * review-integrity signals were missing, so they rendered as raw snake_case
 * — the one part of an insider-risk card a person is most likely to have to
 * explain to the colleague it is about.
 */
const SIGNAL_LABEL: Record<string, string> = {
  sensitive_path: "Sensitive path",
  access_anomaly: "First contribution",
  author_baseline: "Unusual size for this author",
  ai_authorship: "AI authorship",
  privilege_adjacent: "Privilege-adjacent change",
  self_approval: "Approved their own change",
  sole_approver: "Single approver on a sensitive path",
  fast_approval: "Approved faster than the diff could be read",
  unverified_ai: "AI-authored, approved without stated verification",
};

export function InsiderRiskTab({
  repoFullName,
  signals,
  detailIncluded,
  governance,
}: {
  repoFullName: string;
  signals: InsiderRiskSignal[];
  detailIncluded: boolean;
  governance: string;
}) {
  if (signals.length === 0) {
    return (
      <div className="flex flex-col gap-3">
        <EmptyState
          title="No insider-risk assessments"
          detail={
            <>
              Enable the <span className="font-mono">aegis</span> capability to
              get a review prompt on pull requests that touch sensitive paths or
              come from first-time contributors. It never blocks a merge on its
              own and never changes anyone&rsquo;s access.
            </>
          }
        />
        <GovernanceNote note={governance} detailIncluded={detailIncluded} />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <GovernanceNote note={governance} detailIncluded={detailIncluded} />

      <Label>
        {signals.length} assessment{signals.length === 1 ? "" : "s"} for{" "}
        {repoFullName}, newest first
      </Label>

      <ul className="flex flex-col gap-2">
        {signals.map((signal) => (
          <SignalCard key={signal.signal_id} signal={signal} />
        ))}
      </ul>
    </div>
  );
}

function GovernanceNote({
  note,
  detailIncluded,
}: {
  note: string;
  detailIncluded: boolean;
}) {
  return (
    <div className="border-l-2 border-accent bg-accent-wash px-3 py-2">
      <Label>What this is, and is not</Label>
      <p className="mt-1 max-w-prose text-[11px] leading-relaxed text-ink-2">
        {note}
      </p>
      {!detailIncluded ? (
        <p className="mt-1.5 max-w-prose text-[11px] leading-relaxed text-ink-3">
          The author and the signal breakdown are withheld from your role. They
          are not sent to this page at all, rather than hidden in it.
        </p>
      ) : null}
    </div>
  );
}

function SignalCard({ signal }: { signal: InsiderRiskSignal }) {
  const breakdown = signal.signal_breakdown as SignalBreakdown | null;
  const contributing = breakdown?.signals?.filter((s) => s.score > 0) ?? [];

  return (
    <li className="border border-rule bg-paper-2">
      {/* The pull request leads. The author is a field below, not a heading. */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-rule-soft px-3 py-2">
        <span className="font-mono text-[11px] font-bold">
          Pull request #{signal.pr_number}
        </span>
        <Pill tone={RECOMMENDATION_TONE[signal.recommendation] ?? "muted"}>
          {signal.recommendation.replace(/_/g, " ")}
        </Pill>
        <ScoreMeter
          score={signal.insider_risk_score}
          reviewAt={breakdown?.thresholds?.review ?? 40}
          noGoAt={breakdown?.thresholds?.block ?? 80}
        />
        <span className="tabular font-mono text-[10px] text-ink-3">
          {signal.insider_risk_score}/100
        </span>
        {signal.commit_sha ? (
          <span className="font-mono text-[10px] text-ink-3">
            {signal.commit_sha.slice(0, 7)}
          </span>
        ) : null}
        <span className="ml-auto whitespace-nowrap font-mono text-[10px] text-ink-3">
          <RelativeTime value={signal.evaluated_at} />
        </span>
      </div>

      {contributing.length > 0 ? (
        <div className="px-3 py-2">
          <Label>What was observed</Label>
          <ul className="mt-1.5 flex flex-col gap-1">
            {contributing.map((entry) => (
              <li key={entry.key} className="flex gap-2 text-[11px] leading-relaxed">
                <span className="tabular w-9 shrink-0 text-right font-mono text-ink">
                  +{entry.score.toFixed(0)}
                </span>
                <span className="min-w-0">
                  <span className="font-mono text-[10px] text-ink-3">
                    {SIGNAL_LABEL[entry.key] ?? entry.key}
                  </span>
                  <br />
                  <span className="text-ink-2">{entry.rationale}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : breakdown ? (
        <p className="px-3 py-2 text-[11px] text-ink-3">
          No signal scored above zero.
        </p>
      ) : null}

      {breakdown ? <AiAuthorship breakdown={breakdown} /> : null}

      <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-rule-soft px-3 py-1.5 font-mono text-[9px] text-ink-3">
        <span>
          author{" "}
          {signal.author_login ? (
            <span className="text-ink-2">{signal.author_login}</span>
          ) : (
            <span title="Withheld from your role (spec 06 §9)">withheld</span>
          )}
        </span>
        {breakdown?.signals_not_reported?.length ? (
          <span>
            not assessed: {breakdown.signals_not_reported.join(", ")}
          </span>
        ) : null}
        {signal.github_check_run_id ? (
          <span>check run {signal.github_check_run_id}</span>
        ) : (
          <span>not published as a check run</span>
        )}
      </div>
    </li>
  );
}

function AiAuthorship({ breakdown }: { breakdown: SignalBreakdown }) {
  const ai = breakdown.ai_authorship;

  if (!ai.evaluated) {
    return (
      <p className="border-t border-rule-soft px-3 py-2 text-[11px] leading-relaxed text-ink-3">
        <span className="font-mono text-[10px] uppercase tracking-wider">
          AI authorship — not evaluated.
        </span>{" "}
        {ai.reason}
      </p>
    );
  }

  return (
    <p className="border-t border-rule-soft px-3 py-2 text-[11px] leading-relaxed text-ink-2">
      <span className="font-mono text-[10px] uppercase tracking-wider text-ink-3">
        AI authorship —
      </span>{" "}
      {ai.likely_ai_and_undisclosed
        ? "likely AI-generated and not disclosed in the pull request description."
        : "evaluated; no undisclosed AI authorship detected."}
    </p>
  );
}
