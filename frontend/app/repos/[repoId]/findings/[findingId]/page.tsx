import Link from "next/link";

import { getFindingRecord } from "@/lib/server";
import {
  Crumb,
  ErrorPanel,
  Label,
  Pill,
  RelativeTime,
  SeverityText,
} from "@/components/primitives";
import type { Severity } from "@/lib/api";
import type { components } from "@/lib/api-types";
import { PinRegressionTest } from "@/components/pin-regression-test";
import { RemediationAction } from "@/components/remediation-action";

export const dynamic = "force-dynamic";

export const metadata = { title: "Finding — Mykronos" };

/**
 * One finding, with everything the platform knows about it (B-032).
 *
 * Eleven surfaces held pieces of this. Deciding what to do about a single
 * finding meant visiting five pages, and three of the facts that would change
 * the decision — whether a fix exists, whether the lane can close it, whether
 * the code is reachable — were not on the page where the decision got made.
 *
 * The blocks are in the order somebody asks in, which is not the order the data
 * is cheapest to fetch: what is it, does it matter *here*, what do I do, what
 * happened and can it end. Identification is first because it is unavoidable,
 * not because it is the decision — so it gets a header rather than the page.
 */
export default async function FindingRecordPage({
  params,
}: {
  params: Promise<{ repoId: string; findingId: string }>;
}) {
  const { repoId, findingId } = await params;
  const result = await getFindingRecord(findingId);

  if (!result.ok) {
    return <ErrorPanel title="Finding unavailable" detail={result.error} />;
  }

  const { finding, repo_full_name, closure, fix, missing_context } = result.data;
  const here = result.data.severity_here;
  const pkg = result.data.package;

  return (
    <div className="flex flex-col gap-4">
      <div className="font-mono text-[12px] text-ink-3">
        <Crumb href="/">Portfolio</Crumb> /{" "}
        <Crumb href={`/repos/${repoId}`}>{repo_full_name}</Crumb> /{" "}
        <Crumb href={`/repos/${repoId}?tab=findings`}>Findings</Crumb> /{" "}
        <span className="text-ink-2">{finding.rule_id}</span>
      </div>

      <header className="flex flex-col gap-1.5">
        <div className="flex flex-wrap items-baseline gap-2">
          <SeverityText severity={finding.severity as Severity} />
          <Pill tone="muted">{finding.capability}</Pill>
          <Pill tone={finding.status === "open" ? "warn" : "pass"}>{finding.status}</Pill>
          {finding.owner ? (
            <span className="font-mono text-[12px] text-ink-3">
              {finding.owner}
              {finding.owner_source && finding.owner_source !== "codeowners" ? (
                <span
                  className="ml-1"
                  title="Weaker than a CODEOWNERS answer — nobody has claimed this by name."
                >
                  ({finding.owner_source.replace(/_/g, " ")})
                </span>
              ) : null}
            </span>
          ) : null}
        </div>
        <h1 className="max-w-4xl text-xl font-semibold leading-snug">{finding.title}</h1>
        <div className="font-mono text-[12px] text-ink-3">
          {finding.rule_id}
          {pkg ? ` · ${pkg.package_name} ${pkg.installed_version ?? ""}` : ""}
          {finding.file_path ? ` · ${finding.file_path}` : ""}
          {finding.line_start ? `:${finding.line_start}` : ""}
        </div>
      </header>

      {/* Does this matter *here* — starting with what could not be consulted.
          A record that silently omits reachability reads as "not reachable". */}
      {missing_context.length > 0 ? (
        <section className="flex flex-col gap-1 border-l-2 border-high bg-high-wash px-3 py-2">
          <Label as="h2">What this record cannot tell you</Label>
          <ul className="flex flex-col gap-0.5">
            {missing_context.map((gap) => (
              <li key={gap.input} className="text-[13px] leading-relaxed text-ink-2">
                <span className="font-semibold">{gap.input}</span> — {gap.reason}
              </li>
            ))}
          </ul>
          <p className="mt-0.5 text-[13px] text-ink-3">
            Urgency below is severity and threat intelligence, not business risk.
          </p>
        </section>
      ) : null}

      {here ? <SeverityHere here={here} /> : null}

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1.3fr_1fr]">
        <div className="flex flex-col gap-3">
          <section className="border border-rule bg-paper-2">
            <div className="border-b border-rule-soft px-3 py-1.5">
              <Label as="h2">What to do about it</Label>
            </div>
            <div className="px-3 py-2.5">
              {fix ? (
                <>
                  <p className="mb-2 flex flex-wrap items-baseline gap-2 text-[14px]">
                    <Pill tone="accent">{fix.effort.replace(/_/g, " ")}</Pill>
                    <span>
                      Part of a change that closes <strong>{fix.closes}</strong>{" "}
                      finding{fix.closes === 1 ? "" : "s"} in this repository.
                    </span>
                  </p>
                  <ol className="ml-4 list-decimal text-[14px] leading-relaxed">
                    {fix.steps.map((step) => (
                      <li key={step} className="mb-1.5">
                        {step}
                      </li>
                    ))}
                  </ol>
                </>
              ) : (
                <p className="text-[14px] text-ink-3">
                  No grouped remediation covers this rule. What the scanner said
                  is below.
                </p>
              )}
              {pkg ? (
                <p className="mt-3 border-t border-rule-soft pt-2 font-mono text-[12px] text-ink-2">
                  {pkg.package_name} {pkg.installed_version}
                  {pkg.fixable ? (
                    <>
                      {" → "}
                      <span className="text-pass">{pkg.fixed_version}</span>{" "}
                      <span className="text-ink-3">(a fix is published)</span>
                    </>
                  ) : (
                    <span className="text-high"> — no upstream fix published</span>
                  )}
                </p>
              ) : null}
            </div>
          </section>

          {finding.description ? (
            <section className="border border-rule bg-paper-2">
              <div className="border-b border-rule-soft px-3 py-1.5">
                <Label as="h2">What the scanner said</Label>
              </div>
              <pre className="scroll-x px-3 py-2.5 font-mono text-[12px] leading-relaxed text-ink-2">
                {finding.description}
              </pre>
            </section>
          ) : null}
        </div>

        <div className="flex flex-col gap-3">
          {/* The block that earns the page. It exists nowhere else at finding
              level, and it is what stops somebody fixing a defect twice
              because the first fix appeared not to work. */}
          <section
            className={`border bg-paper-2 ${
              closure.can_close ? "border-rule" : "border-critical"
            }`}
          >
            <div className="border-b border-rule-soft px-3 py-1.5">
              <Label as="h2">Can it close?</Label>
            </div>
            <div className="flex flex-col items-start gap-1.5 px-3 py-2.5">
              <Pill tone={closure.can_close ? "pass" : "critical"}>
                {closure.can_close ? "lane healthy" : "blocked"}
              </Pill>
              <p className="text-[13px] leading-relaxed text-ink-2">
                {closure.reason}
              </p>
              <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 font-mono text-[12px]">
                <dt className="text-ink-3">lane</dt>
                <dd>{closure.lane}</dd>
                <dt className="text-ink-3">closes after</dt>
                <dd>{closure.required_absences} consecutive clean scans</dd>
                {closure.last_run_at ? (
                  <>
                    <dt className="text-ink-3">last run</dt>
                    <dd>
                      <RelativeTime value={closure.last_run_at} />
                    </dd>
                  </>
                ) : null}
              </dl>
            </div>
          </section>

          {/* The three actions, on the page that has the finding id — preview
              what auto-remediation would do, open the draft pull request, and
              pin the test that proves it stays fixed.

              Preview before PR is deliberate and is the component's own rule:
              a preview nobody acts on writes nothing, while generating a fix
              opens a branch and a pull request on the real repository. */}
          <section className="border border-rule bg-paper-2">
            <div className="border-b border-rule-soft px-3 py-1.5">
              <Label as="h2">Act on it</Label>
            </div>
            <div className="flex flex-col gap-3 px-3 py-2.5">
              <RemediationAction findingId={findingId} />
              <div className="border-t border-rule-soft pt-3">
                <p className="mb-2 text-[13px] leading-relaxed text-ink-3">
                  Nothing this platform has fixed is protected from coming back
                  silently — 0 of 519 fixed findings here have a test pinned.
                </p>
                <PinRegressionTest findingId={findingId} />
              </div>
            </div>
          </section>

          <section className="border border-rule bg-paper-2">
            <div className="border-b border-rule-soft px-3 py-1.5">
              <Label as="h2">Lifecycle</Label>
            </div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 px-3 py-2.5 font-mono text-[12px]">
              <dt className="text-ink-3">first seen</dt>
              <dd>
                <RelativeTime value={finding.first_seen_at} />
              </dd>
              <dt className="text-ink-3">last seen</dt>
              <dd>
                <RelativeTime value={finding.last_seen_at} />
              </dd>
              <dt className="text-ink-3">owner</dt>
              <dd>{finding.owner ?? "nobody"}</dd>
              <dt className="text-ink-3">due</dt>
              <dd>{finding.due_at ? finding.due_at.slice(0, 10) : "no target set"}</dd>
              <dt className="text-ink-3">identity</dt>
              <dd>{finding.fingerprint_version ?? "—"}</dd>
            </dl>
          </section>

          <p className="text-[13px] leading-relaxed text-ink-3">
            Dispositions, claims and owner changes are made from the{" "}
            <Link
              href={`/repos/${repoId}?tab=findings&finding=${findingId}`}
              className="text-accent underline-offset-2 hover:underline"
            >
              findings tab
            </Link>
            , which holds every occurrence of this rule rather than this one.
          </p>
        </div>
      </div>
    </div>
  );
}

type SeverityHereData = components["schemas"]["SeverityHereOut"];

/**
 * The CVSS score, re-read for this system.
 *
 * A base score is a statement about a vulnerability in the abstract — the same
 * number whether the affected service faces the internet holding card data or
 * sits on a laptop that has been off for a year. This is the standard's own
 * answer to that, computed rather than approximated.
 *
 * **The equal case is the one that needs words.** When nothing is known the two
 * numbers are identical by construction: every undefined modifier takes the
 * base value, so nothing is ever quietly discounted. Showing two matching
 * figures with no explanation would read as "we checked and it matches", which
 * is the opposite of what happened.
 */
function SeverityHere({ here }: { here: SeverityHereData }) {
  const lower = here.environmental < here.base;

  return (
    <section className="border border-rule bg-paper-2">
      <div className="border-b border-rule-soft px-3 py-1.5">
        <Label as="h2">Severity here</Label>
      </div>
      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2 px-3 py-2.5">
        <span className="flex items-baseline gap-2">
          <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
            base
          </span>
          <span className="tabular text-xl font-bold leading-none">
            {here.base.toFixed(1)}
          </span>
        </span>
        <span className="flex items-baseline gap-2">
          <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
            here
          </span>
          <span
            className={`tabular text-xl font-bold leading-none ${
              here.moved ? (lower ? "text-pass" : "text-critical") : ""
            }`}
          >
            {here.environmental.toFixed(1)}
          </span>
        </span>

        <span className="max-w-prose text-[13px] text-ink-2">
          {here.moved ? (
            <>
              {lower ? "Lower" : "Higher"} here because{" "}
              {here.because.join(", ")}.
            </>
          ) : here.stated ? (
            // Stated and unmoved is a real result, not a missing one.
            <>
              Unchanged despite what is known ({here.because.join(", ")}) — the
              impact sub-score is already at its cap.
            </>
          ) : (
            <>
              The same as the base score, because nothing has been stated about
              this system. Every undefined metric takes the base value, so this
              is an upper bound and never a discount.
            </>
          )}
        </span>
      </div>
      <p className="border-t border-rule-soft px-3 py-1.5 font-mono text-[11px] text-ink-3">
        {here.vector}
      </p>
    </section>
  );
}
