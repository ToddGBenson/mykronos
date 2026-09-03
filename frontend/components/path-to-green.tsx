/**
 * What would make this repository go? (spec 26 §1)
 *
 * The term breakdown below this says why the score is what it is. This says
 * what to do about it, which is the question everybody actually asks within
 * four seconds of seeing `no_go` — and which the engine could always answer,
 * since it holds every weight and the exact distance to the threshold.
 *
 * Rendered as a checklist of *findings*, never of outcomes. "Reduce criticals
 * by two" is an instruction nobody can act on directly.
 */

import Link from "next/link";

import { Label, Pill, SeverityText } from "@/components/primitives";
import type { Severity } from "@/lib/api";

type Step = {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: string;
  file_path?: string | null;
  points_removed: number;
  score_after: number;
  recommendation_after: string;
};

type Path = {
  steps?: Step[];
  findings_not_listed?: number;
  reaches?: string;
  note?: string;
};

const BAND_TONE: Record<string, "pass" | "warn" | "critical"> = {
  go: "pass",
  review_recommended: "warn",
  no_go: "critical",
};

export function PathToGreen({ repoId, path }: { repoId: string; path: Path | null }) {
  const steps = path?.steps ?? [];

  if (!path || steps.length === 0) {
    return null;
  }

  const left = path.findings_not_listed ?? 0;

  return (
    <div className="border border-accent bg-paper-2">
      <div className="border-b border-rule-soft bg-accent-wash px-3 py-2">
        <Label>What gets this to go</Label>
        <p className="mt-1 max-w-prose text-[14px] leading-relaxed text-ink-2">
          {path.note}
        </p>
      </div>

      <ol className="flex flex-col">
        {steps.map((step, index) => (
          <li
            key={step.finding_id}
            className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-rule-soft px-3 py-2 last:border-b-0"
          >
            <span className="tabular w-4 font-mono text-[12px] text-ink-3">
              {index + 1}
            </span>
            <SeverityText severity={step.severity as Severity} />
            <Link
              href={`/repos/${repoId}?tab=findings&finding=${step.finding_id}`}
              className="font-mono text-[13px] font-semibold text-ink hover:text-accent"
              title={step.title}
            >
              {step.rule_id}
            </Link>
            {step.file_path ? (
              <span className="font-mono text-[12px] text-ink-3">{step.file_path}</span>
            ) : null}
            <span className="tabular ml-auto font-mono text-[12px] text-pass">
              −{step.points_removed.toFixed(1)}
            </span>
            <span className="tabular font-mono text-[12px] text-ink-3">
              → {step.score_after}
            </span>
            <Pill tone={BAND_TONE[step.recommendation_after] ?? "muted"}>
              {step.recommendation_after.replace(/_/g, " ")}
            </Pill>
          </li>
        ))}
      </ol>

      {left > 0 ? (
        <p className="border-t border-rule-soft px-3 py-2 font-mono text-[12px] text-ink-3">
          {left} further finding{left === 1 ? "" : "s"} not listed — the value here
          is the prefix, not the backlog.
        </p>
      ) : null}
    </div>
  );
}
