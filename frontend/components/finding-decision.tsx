"use client";

/**
 * The decision panel on a finding's page (TheHub #61140, P7).
 *
 * First in the page and sticky beside the evidence: the page exists to make
 * a decision, and the decision used to sit below five panels of evidence,
 * with dispositions on another tab altogether. The recommendation comes first,
 * then the three things a person can do: fix it, say why it does not apply,
 * or accept it formally.
 */

import { useState } from "react";

import { DispositionForm } from "@/components/disposition";
import { RiskAcceptanceForm } from "@/components/risk-acceptance-form";
import type { Recommendation } from "@/lib/finding-decision";

type Choice = "fix" | "dispose" | "accept";

const TONE = { pass: "text-pass", high: "text-high", critical: "text-critical" } as const;

const CHOICES: { value: Choice; label: string }[] = [
  { value: "fix", label: "Fix" },
  { value: "dispose", label: "Not applicable" },
  { value: "accept", label: "Accept risk" },
];

export function FindingDecision({
  findingId,
  status,
  recommendation,
  facts,
  acceptance,
}: {
  findingId: string;
  status: string;
  recommendation: Recommendation;
  /** Short label/value pairs, already worded by the server page. */
  facts: { label: string; value: string; tone?: "pass" | "high" | "critical" }[];
  acceptance: Parameters<typeof RiskAcceptanceForm>[0];
}) {
  const [choice, setChoice] = useState<Choice | null>(
    recommendation.kind === "accept" ? "accept" : recommendation.kind === "fix" ? "fix" : null,
  );
  const open = status === "open";

  return (
    <section
      aria-labelledby="decide-heading"
      className="flex flex-col border border-accent bg-paper-2"
    >
      <div className="flex items-baseline gap-2 border-b border-rule-soft px-3 py-1.5">
        <h2
          id="decide-heading"
          className="font-mono text-[12px] font-bold uppercase tracking-[0.12em]"
        >
          Decide
        </h2>
        <span className="font-mono text-[11px] text-ink-3">{status.replace(/_/g, " ")}</span>
      </div>
      <div className="flex flex-col gap-2.5 px-3 py-2.5">
        <p className="text-[14px] font-semibold leading-snug">{recommendation.text}</p>
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 font-mono text-[12px]">
          {facts.map((f) => (
            <div key={f.label} className="contents">
              <dt className="text-ink-3">{f.label}</dt>
              <dd className={f.tone ? TONE[f.tone] : ""}>{f.value}</dd>
            </div>
          ))}
        </dl>

        {open ? (
          <>
            <div role="group" aria-label="What to do" className="flex flex-wrap gap-1.5">
              {CHOICES.map((c) => (
                <button
                  key={c.value}
                  type="button"
                  aria-pressed={choice === c.value}
                  onClick={() => setChoice(c.value)}
                  className={`min-h-11 border px-3 font-mono text-[12px] font-bold ${
                    choice === c.value
                      ? "border-accent bg-accent-wash text-accent"
                      : "border-rule text-ink-2 hover:border-accent hover:text-accent"
                  }`}
                >
                  {c.label}
                </button>
              ))}
            </div>
            {choice === "fix" ? (
              <p className="text-[13px] leading-relaxed text-ink-2">
                The steps and the remediation actions are in{" "}
                <a href="#act" className="text-accent underline-offset-2 hover:underline">
                  What to do about it
                </a>
                . A fix closes the finding after the lane scans clean; nothing here marks it
                fixed by hand.
              </p>
            ) : null}
            {choice === "dispose" ? (
              <DispositionForm findingId={findingId} currentStatus={status} offerAccept={false} />
            ) : null}
            {choice === "accept" ? <RiskAcceptanceForm {...acceptance} /> : null}
          </>
        ) : null}
      </div>
    </section>
  );
}
