import Link from "next/link";

import { EmptyState, ErrorPanel, Label, Pill } from "@/components/primitives";
import { StalledLanes } from "@/components/stalled-lanes";
import { getBriefing } from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * How do I remediate the open vulnerabilities today? (D-098)
 *
 * Every other surface answers a different question. The portfolio ranks
 * repositories, the worklist ranks findings, vulnerability management reports
 * ageing and acceptance. All four hundred-odd open findings appear on those
 * pages as one undifferentiated pile of work, and none of them says which of
 * it is *actually work today*.
 *
 * On 2026-09-01 the pile was 593 open findings and the honest answer was:
 *
 * - **109 needed nothing.** Already fixed, absent from the newest successful
 *   scan, waiting only on a sweep. Running it closed them.
 * - **316 could not be touched at all** — their lanes are not producing
 *   scans, so nothing closes however thoroughly it is fixed.
 * - **0 were auto-fixable**, and saying so is the point rather than an
 *   apology.
 *
 * So the sections are ordered by effort, cheapest first, and each one states
 * what it would take. A page that sorted by severity would put a critical
 * nobody can close today above 109 findings that close for free.
 */
export const metadata = { title: "Remediate today — Mykronos" };

export default async function RemediatePage() {
  return <RemediateToday />;
}

/**
 * The page body, scoped or not.
 *
 * Exported because the same reasoning answers two different questions. The
 * estate view asks "where is the worst of it"; a repository's own tab asks
 * "what do I do about *this* service today", which is the question somebody
 * who owns one service actually has and the only one they can act on.
 *
 * One component rather than two, and one query behind it, because a scoped
 * view that could disagree with the estate view would be a bug nobody would
 * catch — both would look plausible and only one could be right.
 */
export async function RemediateToday({ repoId }: { repoId?: string } = {}) {
  const briefing = await getBriefing(repoId);
  if (!briefing.ok) {
    return <ErrorPanel title="Cannot answer that right now" detail={briefing.error} />;
  }

  const {
    total_open,
    blocked_findings,
    closing_soon,
    auto_fixable,
    stalled,
    awaiting,
    guidance,
    fixes,
  } = briefing.data;

  // What is left once the free ones and the frozen ones are set aside. This
  // is the only number on the page that means "work a person has to do".
  const actionable = Math.max(0, total_open - closing_soon - blocked_findings);

  return (
    <div className="flex flex-col gap-5">
      <header className="flex flex-col gap-1">
        <h1 className="text-sm font-bold">How to remediate the open findings today</h1>
        <p className="max-w-prose text-[14px] leading-relaxed text-ink-3">
          Ordered by what it costs you, cheapest first — not by severity. A
          critical nobody can close today belongs below {closing_soon} findings
          that close for free.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-2">
        <Pill tone="muted">{total_open} open</Pill>
        <Pill tone={closing_soon > 0 ? "pass" : "muted"}>{closing_soon} closing on their own</Pill>
        <Pill tone={blocked_findings > 0 ? "critical" : "muted"}>{blocked_findings} blocked</Pill>
        <Pill tone={actionable > 0 ? "warn" : "muted"}>{actionable} need a person</Pill>
      </div>

      {/* 1 — free. Always first, because it costs nothing and shrinks the
          number everything else is measured against. */}
      <section className="flex flex-col gap-2">
        <Label>1 · Nothing to do — these close by themselves</Label>
        {awaiting.length === 0 ? (
          <EmptyState
            title="Nothing waiting"
            detail="No open finding is currently absent from its lane's most recent successful scan."
          />
        ) : (
          <>
            <p className="max-w-prose text-[12px] leading-relaxed text-ink-3">
              Already fixed and absent from the newest successful scan. Closure
              is arithmetic from here — two consecutive successful scans, and
              these are counted.
            </p>
            <ul className="flex flex-col gap-1 font-mono text-[12px]">
              {awaiting.map((a) => (
                <li key={`${a.repo_full_name}:${a.capability}`} className="text-ink-2">
                  <strong className="text-ink">{a.findings}</strong> {a.capability} ·{" "}
                  {a.repo_full_name} —{" "}
                  {a.scans_needed === 0 ? (
                    <span className="text-pass">
                      ready now; the next closure sweep takes them
                    </span>
                  ) : (
                    <>needs {a.scans_needed} more successful scan(s)</>
                  )}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      {/* 2 — the blocker. Nothing below this matters for a frozen finding. */}
      <section className="flex flex-col gap-2">
        <Label>2 · Repair these lanes, or the rest cannot close at all</Label>
        {stalled.length === 0 ? (
          <EmptyState
            title="Every lane is reporting"
            detail="Findings can close as they are fixed."
          />
        ) : (
          <>
            <p className="max-w-prose text-[12px] leading-relaxed text-ink-3">
              A finding closes only after two consecutive <em>successful</em>{" "}
              scans see it gone. These lanes are not producing them, so{" "}
              <strong className="text-ink">{blocked_findings} findings</strong>{" "}
              cannot close however thoroughly they are fixed. This is the
              highest-leverage work on the page and none of it is editing code.
            </p>
            <StalledLanes lanes={stalled} />
          </>
        )}
      </section>

      {/* 3 — one level above the rule: the change itself. Two ZAP plugins
          that both want a Content-Security-Policy value are one edit, and
          showing them as two rows asks for the work twice (B-028). */}
      <section className="flex flex-col gap-2">
        <Label>3 · Step by step, one entry per change</Label>
        {fixes.length === 0 ? (
          <EmptyState title="Nothing open" detail="No open findings in scope." />
        ) : (
          <div className="flex flex-col gap-3">
            <p className="max-w-prose text-[12px] leading-relaxed text-ink-3">
              Grouped by the change rather than the finding or the rule. Where
              two scanner rules are answered by one edit, they appear once —
              derived from what the scanner said to do, never from a list kept
              here of which rules are &ldquo;really the same&rdquo;.
            </p>
            {fixes.slice(0, 12).map((fix) => (
              <details
                key={fix.fix_id}
                className="border-l-2 border-rule pl-3"
                open={fix.effort === "config" || fix.effort === "upgrade"}
              >
                <summary className="cursor-pointer list-none">
                  <span className="font-mono text-[13px] text-ink">{fix.action}</span>
                  <span className="ml-2 font-mono text-[12px] text-ink-2">
                    closes {fix.findings}
                  </span>
                  {fix.rules.length > 1 ? (
                    <span className="ml-2 font-mono text-[11px] text-accent">
                      across {fix.rules.length} rules
                    </span>
                  ) : null}
                  <span className="ml-2 text-[10px] uppercase tracking-wide text-ink-3">
                    {fix.effort}
                  </span>
                </summary>
                {fix.steps.length > 0 ? (
                  <ol className="mt-1 flex list-decimal flex-col gap-1 pl-4">
                    {fix.steps.map((step) => (
                      <li
                        key={step.slice(0, 32)}
                        className="max-w-prose text-[12px] leading-relaxed text-ink-2"
                      >
                        {step}
                      </li>
                    ))}
                  </ol>
                ) : (
                  <p className="mt-1 max-w-prose text-[12px] leading-relaxed text-ink-3">
                    No standing procedure for this class — it is a judgement
                    about this finding, and the scanner&rsquo;s own text is in
                    the table below.
                  </p>
                )}
                <p className="mt-1 font-mono text-[11px] text-ink-3">
                  {fix.repos.join(", ")}
                </p>
              </details>
            ))}
          </div>
        )}
      </section>

      {/* 3 — the scanners' own remediation, grouped on the rule because that
          is the unit the fix has. Forty alerts across forty URLs are one
          policy line, and listing them as forty rows is how a five-minute
          change looks like a sprint. */}
      <section className="flex flex-col gap-2">
        <Label>4 · What the scanners said to do, rule by rule</Label>
        {guidance.length === 0 ? (
          <EmptyState title="Nothing open" detail="No open findings in scope." />
        ) : (
          <div className="flex flex-col gap-4">
            <p className="max-w-prose text-[12px] leading-relaxed text-ink-3">
              Taken from the scan itself — ZAP&apos;s <code>solution</code>,
              Trivy&apos;s <code>Fixed Version</code> — not from a general sense
              of what a class of finding usually needs. Each row says which,
              because &ldquo;the tool told us&rdquo; and &ldquo;we think&rdquo;
              do not deserve equal trust.
            </p>
            {guidance.map((cap) => (
              <div key={cap.capability} className="flex flex-col gap-1">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <span className="font-mono text-[13px] font-bold text-ink">
                    {cap.capability}
                  </span>
                  <span className="font-mono text-[12px] text-ink-2">{cap.count} open</span>
                  {cap.unactionable > 0 ? (
                    <span className="font-mono text-[11px] text-ink-3">
                      — {cap.unactionable} with no fix published
                    </span>
                  ) : null}
                </div>
                <div className="scroll-x">
                  <table className="w-full min-w-[680px] border-collapse font-mono text-[12px]">
                    <thead>
                      <tr className="text-left text-ink-3">
                        <th className="px-2 py-1 text-right font-normal">Count</th>
                        <th className="px-2 py-1 font-normal">Finding</th>
                        <th className="px-2 py-1 font-normal">Fix</th>
                      </tr>
                    </thead>
                    <tbody>
                      {cap.rules.map((rule) => (
                        <tr key={rule.rule_id} className="border-t border-rule align-top">
                          <td className="px-2 py-1 text-right text-ink">{rule.count}</td>
                          <td className="px-2 py-1 text-ink-2">
                            {rule.title}
                            <span className="ml-1 text-[10px] uppercase tracking-wide text-ink-3">
                              {rule.effort}
                            </span>
                          </td>
                          <td className="max-w-[46ch] px-2 py-1 leading-snug text-ink-3">
                            {rule.fix}
                            {rule.source === "standing" ? (
                              <span className="ml-1 text-[10px] uppercase tracking-wide text-ink-3">
                                · ours, not the scanner&apos;s
                              </span>
                            ) : null}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* 4 — the honest zero. B-021's lesson: state coverage, or a blank
          table reads as a broken feature. */}
      <section className="flex flex-col gap-2">
        <Label>5 · What auto-remediation can take off you</Label>
        <p className="max-w-prose text-[12px] leading-relaxed text-ink-3">
          <strong className="text-ink">
            {auto_fixable} of {total_open}
          </strong>
          . The four deterministic fixers cover Python, npm and Go dependency
          pinning, and committed secrets. Nothing else in this backlog is a
          class any of them handles, so the pipeline declines rather than
          guesses — which is what it is for. Every fix it does produce is a
          draft pull request a person merges; the client has no merge method
          and a test enforces that.
        </p>
        <p className="text-[12px] text-ink-3">
          <Link href="/remediation" className="text-accent hover:underline">
            Remediation
          </Link>{" "}
          has the per-fixer coverage table.
        </p>
      </section>
    </div>
  );
}
