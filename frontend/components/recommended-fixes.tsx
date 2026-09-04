import { EmptyState, Label, Pill } from "@/components/primitives";
import type { RepoGuidance } from "@/lib/api";

/**
 * What the scanners recommend for this repository, and the fix each points to
 * (B-030).
 *
 * The Remediation tab below this says what Patchwork did and did not do. That
 * is honest and it is half the picture: four deterministic fixers cover four
 * narrow classes, so across this estate the truthful answer is almost always
 * "nothing" — a tab reporting zero, beside scan reports full of remediation
 * advice nobody was reading.
 *
 * This is the other half, and it is not Patchwork's. Every line comes from the
 * report itself: ZAP's `solution`, Trivy's `Fixed Version`. Where the platform
 * supplies the wording instead — gitleaks reports a match and no remedy — the
 * row says so, because "the tool told us" and "we think" do not deserve equal
 * trust.
 *
 * **Grouped by the change, not the finding.** Two ZAP plugins that both want a
 * Content-Security-Policy value are one edit; two advisories against one
 * package are one upgrade to the higher version. Listed per finding, a
 * five-minute change looks like a sprint.
 */
export function RecommendedFixes({ data }: { data: RepoGuidance }) {
  const { fixes, actionable_findings } = data;

  if (fixes.length === 0) {
    return (
      <EmptyState
        title="Nothing open to recommend a fix for"
        detail="No open finding in this repository carries remediation advice, which usually means there is nothing open at all."
      />
    );
  }

  // Cheapest first is already the API's order. The split is only for the
  // heading: "you can do these today" is a different sentence from "these are
  // judgements", and running them together is what makes a list feel like a
  // backlog rather than a morning.
  const now = fixes.filter((f) => f.effort === "config" || f.effort === "upgrade");
  const rest = fixes.filter((f) => f.effort !== "config" && f.effort !== "upgrade");

  return (
    <section className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline gap-3">
        <Label>Recommended fixes</Label>
        <span className="font-mono text-[12px] text-ink-3">
          from the scan reports, grouped by the change
        </span>
        {actionable_findings > 0 ? (
          <Pill tone="warn">{actionable_findings} closable today</Pill>
        ) : null}
      </div>

      {now.length > 0 ? (
        <div className="flex flex-col gap-2">
          <p className="max-w-prose text-[12px] leading-relaxed text-ink-2">
            <strong className="text-ink">These need no judgement.</strong> A
            config value or a version bump, each closing every finding under it.
          </p>
          {now.map((fix) => (
            <Fix key={fix.fix_id} fix={fix} open />
          ))}
        </div>
      ) : null}

      {rest.length > 0 ? (
        <div className="flex flex-col gap-2 border-t border-rule pt-2">
          <p className="max-w-prose text-[12px] leading-relaxed text-ink-3">
            The rest are judgements about this codebase. The scanner&rsquo;s own
            wording is here so the decision starts from what the tool actually
            said, rather than from a rule id.
          </p>
          {rest.slice(0, 10).map((fix) => (
            <Fix key={fix.fix_id} fix={fix} open={false} />
          ))}
          {rest.length > 10 ? (
            <p className="font-mono text-[11px] text-ink-3">
              …and {rest.length - 10} more. The full list is on{" "}
              <span className="text-ink-2">Remediate today</span>.
            </p>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

function Fix({
  fix,
  open,
}: {
  fix: RepoGuidance["fixes"][number];
  open: boolean;
}) {
  return (
    <details className="border-l-2 border-rule pl-3" open={open}>
      <summary className="cursor-pointer list-none">
        <span className="font-mono text-[13px] text-ink">{fix.action}</span>
        <span className="ml-2 font-mono text-[12px] text-ink-2">
          closes {fix.findings}
        </span>
        {/* More than one rule is the whole reason grouping by fix exists, so
            it is said rather than left to be noticed. */}
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
          No standing procedure for this class — it is a judgement about this
          finding, and the scanner&rsquo;s own text is what to start from.
        </p>
      )}

      <p className="mt-1 font-mono text-[11px] text-ink-3">
        {fix.rules.slice(0, 4).join(", ")}
        {fix.rules.length > 4 ? ` +${fix.rules.length - 4}` : ""}
      </p>
    </details>
  );
}
