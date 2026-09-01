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
  const briefing = await getBriefing();
  if (!briefing.ok) {
    return <ErrorPanel title="Cannot answer that right now" detail={briefing.error} />;
  }

  const { total_open, blocked_findings, closing_soon, auto_fixable, stalled, classes, awaiting } =
    briefing.data;

  // What is left once the free ones and the frozen ones are set aside. This
  // is the only number on the page that means "work a person has to do".
  const actionable = Math.max(0, total_open - closing_soon - blocked_findings);

  return (
    <div className="flex flex-col gap-5">
      <header className="flex flex-col gap-1">
        <h1 className="text-sm font-bold">How to remediate the open findings today</h1>
        <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
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
            <p className="max-w-prose text-[10px] leading-relaxed text-ink-3">
              Already fixed and absent from the newest successful scan. Closure
              is arithmetic from here — two consecutive successful scans, and
              these are counted.
            </p>
            <ul className="flex flex-col gap-1 font-mono text-[10px]">
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
            <p className="max-w-prose text-[10px] leading-relaxed text-ink-3">
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

      {/* 3 — real work, grouped so one action covers many findings. */}
      <section className="flex flex-col gap-2">
        <Label>3 · Real work, grouped by what would fix it</Label>
        {classes.length === 0 ? (
          <EmptyState title="Nothing open" detail="No open findings in scope." />
        ) : (
          <div className="flex flex-col gap-3">
            {classes.map((entry) => (
              <div key={entry.capability} className="border-l-2 border-rule pl-3">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <span className="font-mono text-[11px] text-ink">{entry.open_findings}</span>
                  <span className="font-mono text-[10px] text-ink-2">{entry.capability}</span>
                </div>
                <p className="mt-0.5 max-w-prose text-[10px] leading-relaxed text-ink-3">
                  {entry.route}
                </p>
                {entry.concentrated_in.length > 0 ? (
                  <p className="mt-0.5 max-w-prose text-[9px] leading-snug text-ink-3">
                    Concentrated in:{" "}
                    {entry.concentrated_in.map(([name, n]) => `${name} (${n})`).join(", ")} — which
                    is what turns a count into one action.
                  </p>
                ) : null}
                {entry.action ? (
                  <p className="mt-1 font-mono text-[9px] text-accent">
                    → {entry.action.method} {entry.action.path}
                  </p>
                ) : (
                  <p className="mt-1 text-[9px] text-ink-3">
                    No single request does this one — see above for what does.
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* 4 — the honest zero. B-021's lesson: state coverage, or a blank
          table reads as a broken feature. */}
      <section className="flex flex-col gap-2">
        <Label>4 · What auto-remediation can take off you</Label>
        <p className="max-w-prose text-[10px] leading-relaxed text-ink-3">
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
        <p className="text-[10px] text-ink-3">
          <Link href="/remediation" className="text-accent hover:underline">
            Remediation
          </Link>{" "}
          has the per-fixer coverage table.
        </p>
      </section>
    </div>
  );
}
