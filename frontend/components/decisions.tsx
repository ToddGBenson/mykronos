/**
 * Oracle's decision history for one repository.
 *
 * The point of this view is not the verdict — that already appeared on the
 * pull request as a Check Run. It is that the verdict is *checkable*: the
 * arithmetic, the policy version, what the human did about it, and what
 * happened to the pull request afterwards. A risk score nobody can audit is
 * one people learn to route around.
 */

import {
  EmptyState,
  Label,
  Pill,
  RelativeTime,
  ScoreMeter,
  Verdict,
} from "@/components/primitives";
import { OverrideDecision } from "@/components/override-decision";
import type { RiskDecision } from "@/lib/api";

const DECISION_TYPE_LABEL: Record<string, string> = {
  pr_gate: "pull request",
  release_gate: "release",
  portfolio: "standing",
};

/** What happened to the pull request after Oracle judged it (D-021). */
const OUTCOME_LABEL: Record<string, string> = {
  merged: "merged",
  closed_unmerged: "closed unmerged",
};

export function DecisionsTab({
  repoFullName,
  decisions,
}: {
  repoFullName: string;
  decisions: RiskDecision[];
}) {
  if (decisions.length === 0) {
    return (
      <EmptyState
        title="No risk decision for this repository yet"
        detail={
          <>
            Enable the <span className="font-mono">oracle</span> capability to
            get a decision on every pull request, plus a standing score once a
            day. Scanning without it is deliberate and supported — consent to
            being scanned is not consent to being scored.
          </>
        }
      />
    );
  }

  // Every no_go that merged anyway. Surfaced above the list because it is the
  // one thing here that argues for changing how the platform is configured.
  const wouldHaveBlocked = decisions.filter(
    (d) => d.recommendation === "no_go" && d.gate_outcome === "merged",
  ).length;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline gap-3 text-[11px]">
        <Label>
          {decisions.length} decision{decisions.length === 1 ? "" : "s"} for{" "}
          {repoFullName}
        </Label>
        {wouldHaveBlocked > 0 ? (
          <span className="border-l-2 border-high bg-high-wash px-2 py-1 text-ink-2">
            <strong className="text-high">{wouldHaveBlocked}</strong> merged
            despite a <span className="font-mono">no go</span> — what blocking
            mode would have stopped.
          </span>
        ) : null}
      </div>

      <ul className="flex flex-col gap-2">
        {decisions.map((decision) => (
          <DecisionCard key={decision.decision_id} decision={decision} />
        ))}
      </ul>
    </div>
  );
}

function DecisionCard({ decision }: { decision: RiskDecision }) {
  const terms = decision.inputs_snapshot?.terms ?? [];
  const totals = decision.inputs_snapshot?.totals;
  const override = decision.human_override ?? null;

  return (
    <li className="border border-rule bg-paper-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-rule-soft px-3 py-2">
        <Verdict
          recommendation={decision.recommendation}
          score={decision.overall_risk_score}
        />
        <ScoreMeter score={decision.overall_risk_score} />

        <span className="font-mono text-[10px] text-ink-3">
          {DECISION_TYPE_LABEL[decision.decision_type] ?? decision.decision_type}
          {decision.pr_number ? ` #${decision.pr_number}` : ""}
          {decision.release_tag ? ` ${decision.release_tag}` : ""}
          {decision.commit_sha ? ` · ${decision.commit_sha.slice(0, 7)}` : ""}
        </span>

        {decision.gate_outcome ? (
          <Pill tone={decision.gate_outcome === "merged" ? "muted" : "pass"}>
            {OUTCOME_LABEL[decision.gate_outcome] ?? decision.gate_outcome}
          </Pill>
        ) : null}

        {override ? <Pill tone="accent">overridden</Pill> : null}

        <span className="ml-auto whitespace-nowrap font-mono text-[10px] text-ink-3">
          <RelativeTime value={decision.evaluated_at} />
        </span>
      </div>

      {/* Capped rather than full-bleed: on a wide screen an uncapped line of
          reasoning is a single 250-character row nobody finishes reading. */}
      <p className="max-w-prose px-3 py-2 text-[11px] leading-relaxed text-ink-2">
        {decision.reasoning}
      </p>

      {terms.length > 0 ? (
        <div className="border-t border-rule-soft px-3 py-2">
          <Label>How this score was reached</Label>
          <table className="mt-1.5 w-auto border-collapse font-mono text-[10px]">
            <tbody>
              {terms.map((term) => (
                <tr key={term.label}>
                  {/* Signed, because the model can now subtract as well as
                      add (spec 26 §2), and a credit rendered as `+-1.5` reads
                      as a formatting bug rather than as points earned back. */}
                  <td
                    className={`tabular w-14 py-0.5 pr-3 text-right ${
                      term.contribution < 0 ? "text-pass" : "text-ink"
                    }`}
                  >
                    {term.contribution < 0 ? "−" : "+"}
                    {Math.abs(term.contribution).toFixed(1)}
                  </td>
                  <td className="py-0.5 pr-6 text-ink-2">{term.label}</td>
                  <td className="py-0.5 text-ink-3">{term.detail}</td>
                </tr>
              ))}
              {totals ? (
                <tr className="border-t border-rule-soft">
                  <td className="tabular w-14 py-0.5 pr-3 text-right font-bold">
                    {totals.overall_risk_score}
                  </td>
                  <td className="py-0.5 pr-6 font-bold text-ink-2">final</td>
                  <td className="py-0.5 text-ink-3">
                    {totals.clamped
                      ? `clamped from ${totals.raw_score.toFixed(1)}`
                      : "within range"}
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      ) : null}

      {override ? (
        <div className="border-t border-rule-soft bg-accent-wash px-3 py-2">
          <Label>Override</Label>
          <p className="mt-1 max-w-prose text-[11px] leading-relaxed text-ink-2">
            {override.reason}
          </p>
          <p className="mt-1 font-mono text-[10px] text-ink-3">
            {override.overridden_by} · {override.original_recommendation} →{" "}
            {override.accepted_recommendation} ·{" "}
            <RelativeTime value={override.overridden_at} />
          </p>
        </div>
      ) : (
        // Only where there is not one already: overrides are append-only
        // history, and the endpoint 409s on a second attempt. Offering the
        // button anyway would be offering a click that cannot work.
        <OverrideDecision
          decisionId={decision.decision_id}
          recommendation={decision.recommendation}
        />
      )}

      <p className="border-t border-rule-soft px-3 py-1.5 font-mono text-[9px] text-ink-3">
        policy {decision.policy_version} · {decision.decision_id}
        {decision.github_check_run_id
          ? ` · check run ${decision.github_check_run_id}`
          : " · not published as a check run"}
      </p>
    </li>
  );
}
