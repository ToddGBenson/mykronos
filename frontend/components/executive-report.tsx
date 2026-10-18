/**
 * The Executive report tab: one repository's security posture on one page,
 * in words a non-specialist can act on, and printable as it stands.
 *
 * Every number is a field of the executive-summary response, read when the
 * page was requested; nothing is counted here. Where the platform cannot
 * answer -- no history that far back, a scanner that never ran -- the page
 * says so in the place the number would have gone, because a printed page is
 * read without anyone on hand to explain a blank.
 *
 * Printing is the browser's own: `data-print-report` switches on the print
 * rules in `globals.css`, which hide the navigation, force the light palette
 * and keep each section on one page where it fits.
 */

import type { ReactNode } from "react";

import { CAPABILITY_META, Pill, Section, SeverityText } from "@/components/primitives";
import { PrintButton } from "@/components/print-button";
import { SEVERITY_ORDER } from "@/lib/api";
import {
  FIX_BUCKETS,
  SCANNER_GLOSS,
  change,
  formatWhen,
  headline,
  laneIsDoubtful,
  laneIsStalled,
  laneStatusText,
  plural,
} from "@/lib/executive-report";
import type { ExecutiveSummary } from "@/lib/server";

function label(capability: string): string {
  return (
    (CAPABILITY_META as Record<string, { label: string }>)[capability]?.label ?? capability
  );
}

function n(value: number): string {
  return value.toLocaleString("en-US");
}

/** Prose blocks inside a Section, padded the way the other tabs pad theirs. */
function Body({ children }: { children: ReactNode }) {
  return <div className="flex flex-col gap-2 px-3 py-2.5 text-[14px] leading-relaxed">{children}</div>;
}

function Gloss({ children }: { children: ReactNode }) {
  return <p className="max-w-prose text-[13px] text-ink-3">{children}</p>;
}

export function ExecutiveReport({ data }: { data: ExecutiveSummary }) {
  const [week, month] = data.trend;
  const serious = (data.open_by_severity.critical ?? 0) + (data.open_by_severity.high ?? 0);
  const doubtful = data.lanes.filter(laneIsDoubtful);
  const stalled = data.lanes.filter(laneIsStalled);
  const never = doubtful.filter((lane) => !laneIsStalled(lane));
  const fixability = Object.fromEntries(data.fixability.map((b) => [b.key, b]));
  const accepted = data.accepted;
  const progress = data.progress;

  return (
    <article data-print-report className="flex flex-col gap-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <p className="font-mono text-[12px] uppercase tracking-[0.12em] text-ink-3">
            Security posture report
          </p>
          <h2 className="font-mono text-lg font-bold">{data.repo_full_name}</h2>
          <p className="text-[13px] text-ink-3">
            Read from Mykronos&rsquo;s records on {formatWhen(data.generated_at)}.
            {data.history_since
              ? ` Scanning history from ${formatWhen(data.history_since, false)}.`
              : ""}
          </p>
        </div>
        <PrintButton />
      </header>

      <p className="max-w-3xl border-l-4 border-accent bg-paper-2 px-4 py-3 text-[17px] font-medium leading-snug text-ink">
        {headline(data)}
      </p>

      {/* 1. Open risk by severity, against a week and a month ago. */}
      <Section title="Open risk by severity" detail="now, and against 7 and 30 days ago">
        <div className="scroll-x px-3 py-2">
          <table className="w-full max-w-2xl text-[13px] tabular">
            <thead>
              <tr className="border-b border-rule text-left font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
                <th className="py-1 pr-3 font-normal">Severity</th>
                <th className="py-1 pr-3 text-right font-normal">Open now</th>
                <th className="py-1 pr-3 text-right font-normal">7 days ago</th>
                <th className="py-1 pr-3 text-right font-normal">change</th>
                <th className="py-1 pr-3 text-right font-normal">30 days ago</th>
                <th className="py-1 text-right font-normal">change</th>
              </tr>
            </thead>
            <tbody>
              {SEVERITY_ORDER.map((severity) => {
                const now = data.open_by_severity[severity] ?? 0;
                const then7 = week?.open_by_severity?.[severity] ?? null;
                const then30 = month?.open_by_severity?.[severity] ?? null;
                return (
                  <tr key={severity} className="border-b border-rule-soft">
                    <td className="py-1 pr-3">
                      <SeverityText severity={severity} />
                    </td>
                    <td className="py-1 pr-3 text-right font-bold">{n(now)}</td>
                    <td className="py-1 pr-3 text-right">{then7 === null ? "—" : n(then7)}</td>
                    <td className="py-1 pr-3 text-right text-ink-3">{change(now, then7)}</td>
                    <td className="py-1 pr-3 text-right">{then30 === null ? "—" : n(then30)}</td>
                    <td className="py-1 text-right text-ink-3">{change(now, then30)}</td>
                  </tr>
                );
              })}
              <tr className="font-bold">
                <td className="py-1 pr-3 font-mono text-[12px] uppercase">Total</td>
                <td className="py-1 pr-3 text-right">{n(data.open_total)}</td>
                <td className="py-1 pr-3 text-right">
                  {week?.open_total == null ? "—" : n(week.open_total)}
                </td>
                <td className="py-1 pr-3 text-right font-normal text-ink-3">
                  {change(data.open_total, week?.open_total)}
                </td>
                <td className="py-1 pr-3 text-right">
                  {month?.open_total == null ? "—" : n(month.open_total)}
                </td>
                <td className="py-1 text-right font-normal text-ink-3">
                  {change(data.open_total, month?.open_total)}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Body>
          {data.trend.some((point) => !point.available) ? (
            <p className="text-high">
              {data.history_since
                ? `No trend for ${data.trend
                    .filter((p) => !p.available)
                    .map((p) => `${p.days_ago} days ago`)
                    .join(" or ")}: scanning history only starts on ${formatWhen(
                    data.history_since,
                    false,
                  )}. A dash means "not measured", not zero.`
                : "No trend: this repository has never been scanned."}
            </p>
          ) : null}
          <Gloss>
            An <em>issue</em> is one problem a scanner reported that has not been closed.{" "}
            <em>Severity</em> is the scanner&rsquo;s rating of how much harm it could do if
            exploited. Earlier figures are rebuilt from when each issue was first seen and
            when it was closed, not from stored snapshots.
          </Gloss>
        </Body>
      </Section>

      {/* 2. Concentrations. */}
      <Section
        title="What's driving it"
        detail={
          data.drivers_basis === "critical_high"
            ? `where the ${n(data.drivers_basis_total)} critical and high-severity issues come from`
            : data.drivers_basis === "all_open"
              ? `where the ${n(data.drivers_basis_total)} open issues come from`
              : "nothing is open"
        }
      >
        <Body>
          {data.drivers.length === 0 ? (
            <p className="text-ink-3">Nothing is open, so nothing is concentrated.</p>
          ) : (
            <>
              <ul className="flex flex-col gap-1.5">
                {data.drivers.map((driver) => (
                  <li
                    key={`${driver.capability}:${driver.kind}:${driver.name}`}
                    className="flex flex-wrap items-baseline gap-x-2"
                  >
                    <span className="tabular min-w-[7ch] font-bold">
                      {n(driver.findings)} of {n(data.drivers_basis_total)}
                    </span>
                    <span>
                      {driver.kind === "image"
                        ? "from one container image, "
                        : driver.kind === "package"
                          ? "from one software package, "
                          : `from one ${label(driver.capability)} rule, `}
                      <span className="break-all font-mono text-[12px]">{driver.name}</span>
                    </span>
                    {driver.critical || driver.high ? (
                      <span className="font-mono text-[12px] text-ink-3">
                        ({[
                          driver.critical ? `${n(driver.critical)} critical` : "",
                          driver.high ? `${n(driver.high)} high` : "",
                        ]
                          .filter(Boolean)
                          .join(", ")}
                        )
                      </span>
                    ) : null}
                  </li>
                ))}
              </ul>
              <p className="text-[13px] text-ink-2">
                By scanner:{" "}
                {Object.entries(data.basis_by_capability)
                  .sort(([, a], [, b]) => b - a)
                  .map(([capability, count]) => `${label(capability)} ${n(count)}`)
                  .join(" · ")}
                .
              </p>
            </>
          )}
          <Gloss>
            Grouped by what would be fixed once: a container image is rebuilt once, a
            package is upgraded once, a rule is usually one change in one place.
          </Gloss>
        </Body>
      </Section>

      {/* 3. Fixable, waiting, accepted. */}
      <Section title="Can it be fixed?" detail="open issues, by whether anyone can act on them today">
        <div data-print-keep className="grid gap-2 px-3 pt-2.5 sm:grid-cols-3">
          {FIX_BUCKETS.map((bucket) => {
            const entry = fixability[bucket.key];
            return (
              <div key={bucket.key} className="ticks flex flex-col gap-1 border border-rule bg-paper p-2.5">
                <span className="font-mono text-[12px] uppercase tracking-[0.12em] text-ink-3">
                  {bucket.label}
                </span>
                <span className="tabular text-2xl font-bold leading-none">
                  {n(entry?.findings ?? 0)}
                </span>
                <span className="font-mono text-[11px] text-ink-3">
                  {n(entry?.serious ?? 0)} critical or high
                </span>
                <span className="text-[12px] leading-snug text-ink-2">{bucket.gloss}</span>
              </div>
            );
          })}
        </div>
        <Body>
          {data.closing_on_their_own > 0 ? (
            <p>
              <strong>{plural(data.closing_on_their_own, "open issue")}</strong>{" "}
              {data.closing_on_their_own === 1 ? "is" : "are"} already gone from the latest scan
              and will close on their own once the next scan confirms it.
            </p>
          ) : null}
          <p>
            <strong>Accepted risk:</strong>{" "}
            {accepted.findings === 0 ? (
              "no issues have been accepted as known risks."
            ) : (
              <>
                {plural(accepted.findings, "issue")} ({n(accepted.serious)} critical or high) have
                been accepted as known risks
                {accepted.decisions_active
                  ? `, under ${plural(accepted.decisions_active, "active decision")}`
                  : ""}
                .{" "}
                {accepted.next_expiries.length ? (
                  <>
                    Next review dates:{" "}
                    {accepted.next_expiries
                      .map((e) => `${formatWhen(e.on, false)} (${n(e.findings)})`)
                      .join(", ")}
                    .
                  </>
                ) : null}
                {accepted.nearest_decision_expiry
                  ? ` The first decision expires on ${formatWhen(accepted.nearest_decision_expiry, false)}.`
                  : ""}
              </>
            )}
          </p>
          {accepted.overdue || accepted.no_review_date || accepted.now_fixable ? (
            <ul className="list-disc pl-5 text-[13px] text-high">
              {accepted.overdue ? (
                <li>
                  {plural(accepted.overdue, "acceptance is", "acceptances are")} past the review
                  date and still in force.
                </li>
              ) : null}
              {accepted.no_review_date ? (
                <li>
                  {plural(accepted.no_review_date, "acceptance has", "acceptances have")} no review
                  date, so nobody is scheduled to look again.
                </li>
              ) : null}
              {accepted.now_fixable ? (
                <li>
                  {plural(accepted.now_fixable, "issue was", "issues were")} accepted because no fix
                  existed, and one has since been published.
                </li>
              ) : null}
            </ul>
          ) : null}
          <Gloss>
            <em>Accepted risk</em> is a recorded decision by a person to live with an issue until
            a set date, usually because no fix exists. It is not counted as open, and the issue
            reopens for review when the date arrives.
          </Gloss>
        </Body>
      </Section>

      {/* 4. Coverage. */}
      <Section
        title="Coverage"
        detail="which scanners run, and when each last reported"
        aside={
          doubtful.length ? (
            <Pill tone="warn">{doubtful.length} not reporting normally</Pill>
          ) : data.lanes.length ? (
            <Pill tone="pass">all reporting</Pill>
          ) : null
        }
      >
        {data.lanes.length === 0 ? (
          <Body>
            <p className="text-high">
              No scanner is enabled for this repository, so nothing on this page covers it.
            </p>
          </Body>
        ) : (
          <div className="scroll-x px-3 py-2">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-rule text-left font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
                  <th className="py-1 pr-3 font-normal">Scanner</th>
                  <th className="py-1 pr-3 font-normal">State</th>
                  <th className="py-1 pr-3 font-normal">Last ran</th>
                  <th className="py-1 pr-3 font-normal">Last succeeded</th>
                  <th className="py-1 text-right font-normal">Open</th>
                </tr>
              </thead>
              <tbody>
                {data.lanes.map((lane) => (
                  <tr key={lane.capability} className="border-b border-rule-soft align-top">
                    <td className="py-1 pr-3">
                      <span className="font-semibold">{label(lane.capability)}</span>
                      <span className="block text-[12px] text-ink-3">
                        {SCANNER_GLOSS[lane.capability] ?? ""}
                      </span>
                    </td>
                    <td className={`py-1 pr-3 ${laneIsDoubtful(lane) ? "font-semibold text-high" : ""}`}>
                      {laneStatusText(lane)}
                    </td>
                    <td className="py-1 pr-3 whitespace-nowrap">{formatWhen(lane.last_run_at)}</td>
                    <td className="py-1 pr-3 whitespace-nowrap">{formatWhen(lane.last_success_at)}</td>
                    <td className="tabular py-1 text-right">{n(lane.open_findings)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Body>
          {stalled.length ? (
            <p className="text-high">
              {stalled.map((lane) => label(lane.capability)).join(", ")}:{" "}
              {stalled.length === 1 ? "its" : "their"} numbers cannot be taken as current. An issue
              closes only when two successful scans in a row no longer see it, so a scanner that
              is not running can neither find new problems nor confirm old ones fixed.
            </p>
          ) : null}
          {never.length ? (
            <p className="text-high">
              {never.map((lane) => label(lane.capability)).join(", ")}:{" "}
              enabled but never run, so nothing is known about what{" "}
              {never.length === 1 ? "it" : "they"} would find. A zero there is not a clean result.
            </p>
          ) : null}
          <Gloss>
            A scanner that is not running reports nothing, which looks exactly like finding
            nothing. That is why this table sits beside the counts rather than behind them.
          </Gloss>
        </Body>
      </Section>

      {/* 5. Progress. */}
      <Section
        title="Recent progress"
        detail={`the last ${progress.days} days${
          progress.window_starts ? `, since scanning began on ${formatWhen(progress.window_starts, false)}` : ""
        }`}
      >
        <Body>
          <dl className="grid max-w-2xl grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[14px]">
            <dt className="tabular text-right font-bold">{n(progress.fixed)}</dt>
            <dd>
              fixed ({n(progress.fixed_serious)} critical or high): two successful scans in a row
              no longer saw them
            </dd>
            <dt className="tabular text-right font-bold">{n(progress.false_positive)}</dt>
            <dd>dismissed by a person as false alarms</dd>
            <dt className="tabular text-right font-bold">{n(progress.accepted)}</dt>
            <dd>accepted as known risks</dd>
            <dt className="tabular text-right font-bold">{n(progress.new)}</dt>
            <dd>newly found ({n(progress.new_serious)} critical or high)</dd>
          </dl>
          {progress.reidentified ? (
            <Gloss>
              Not counted above: {plural(progress.reidentified, "record was", "records were")}{" "}
              replaced by a new record for the same problem, which happens when code moves or a
              scanner changes how it names things. That is neither a fix nor a new issue.
            </Gloss>
          ) : null}
        </Body>
      </Section>

      {/* 6. Decisions. */}
      <Section title="Decisions needed" detail="waiting on a person">
        <Body>
          {data.decisions.length === 0 && !accepted.now_fixable ? (
            <p>Nothing is waiting on a decision.</p>
          ) : (
            <ul className="flex flex-col gap-1.5">
              {data.decisions.map((decision) => (
                <li key={`${decision.kind}:${decision.id}`} className="flex flex-col">
                  <span>
                    <strong>
                      {decision.kind === "acceptance_review"
                        ? "Review an accepted risk"
                        : decision.duty === "pull_request_merge"
                          ? "Approve a code change"
                          : decision.duty === "risk_acceptance"
                            ? "Approve a risk acceptance"
                            : decision.duty === "finding_disposition"
                              ? "Approve closing an issue"
                              : "Approve a request"}
                      :
                    </strong>{" "}
                    {decision.summary || decision.id}
                  </span>
                  <span className={`font-mono text-[12px] ${decision.overdue ? "text-critical" : "text-ink-3"}`}>
                    {decision.due
                      ? `${decision.overdue ? "overdue since" : "due by"} ${formatWhen(decision.due, false)}`
                      : "no due date"}
                  </span>
                </li>
              ))}
              {accepted.now_fixable ? (
                <li>
                  <strong>Revisit accepted risks:</strong>{" "}
                  {plural(accepted.now_fixable, "issue was", "issues were")} accepted because no fix
                  existed, and a fix now does.
                </li>
              ) : null}
            </ul>
          )}
        </Body>
      </Section>

      {data.gaps.length ? (
        <Section title="What this report cannot tell you">
          <Body>
            <ul className="list-disc pl-5 text-[13px] text-ink-2">
              {data.gaps.map((gap) => (
                <li key={gap}>{gap}</li>
              ))}
            </ul>
          </Body>
        </Section>
      ) : null}

      <p className="text-[12px] text-ink-3">
        {serious
          ? "Critical and high are the two most severe of five ratings (critical, high, medium, low, info). "
          : ""}
        Every figure on this page was read from the platform when the page was requested; none is
        estimated.
      </p>
    </article>
  );
}
