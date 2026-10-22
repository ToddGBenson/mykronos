import Link from "next/link";
import type { ReactNode } from "react";

import {
  CoveredFinding,
  Expiry,
  FixAvailability,
  PremiseVerdict,
  SeverityPair,
} from "@/components/accepted-risk";
import { EmptyState, ErrorPanel, Label, Pill, RelativeTime } from "@/components/primitives";
import type { RiskAcceptanceRow } from "@/lib/api";
import {
  STRIP_STATES,
  controlText,
  filterHref,
  reasonLabel,
  severityCounts,
  reviewDueLabel,
  stateLabel,
  stateTone,
  type RiskFilters,
} from "@/lib/risk-acceptances";
import { getRepoRiskAcceptances } from "@/lib/server";

/**
 * Risk management: every risk this repository accepted, what each acceptance
 * rests on, and whether that still holds.
 *
 * Not the Risk Decision tab beside it - that is Oracle's ship/no-ship score.
 * This is the register of decisions *not* to fix: one row per acceptance
 * (a decision covering one finding or thousands), with the premises the
 * premise monitor evaluates on every read, so a premise that failed this
 * morning reads failed here now rather than at the next nightly run.
 *
 * Filters are URL parameters, server-rendered like every other tab: the
 * counts in the strip are links, and a lit one clears itself.
 */
export async function RiskManagementTab({
  repoId,
  query,
}: {
  repoId: string;
  query: Record<string, string | undefined>;
}) {
  const filters: RiskFilters = {
    state: query.state || undefined,
    severity: query.severity || undefined,
    effective: query.effective || undefined,
  };
  const result = await getRepoRiskAcceptances(repoId, filters);
  if (!result.ok) {
    return <ErrorPanel title="Risk acceptances unavailable" detail={result.error} />;
  }
  const data = result.data;
  if (data.total === 0) {
    return (
      <EmptyState
        title="Nothing accepted in this repository."
        detail="No risk acceptance has been proposed for any finding here. An acceptance is proposed through the acceptance API and takes effect only once someone independent approves it."
      />
    );
  }
  const filtered = Boolean(filters.state || filters.severity || filters.effective);
  const byState = data.counts.by_state;
  const otherStates = Object.entries(byState).filter(
    ([state, count]) => count > 0 && !(STRIP_STATES as readonly string[]).includes(state),
  );

  return (
    <div className="flex flex-col gap-4">
      <p className="max-w-prose text-[14px] leading-relaxed text-ink-3">
        Every risk accepted in {data.repo_full_name}, what each acceptance rests on,
        and whether that still holds. Premises are re-checked against the latest
        evidence on every load (fresh means collected within {data.premise_fresh_days}{" "}
        days); <em>unverified</em> means nothing fresh says either way, which is not
        the same as holding. &ldquo;Expiring&rdquo; is {data.expiring_within_days} days
        or fewer left.
      </p>

      <div className="flex flex-col gap-2 border border-rule bg-paper-2 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <Label>State</Label>
          {STRIP_STATES.map((state) => (
            <StripLink
              key={state}
              href={filterHref(repoId, filters, "state", state)}
              active={filters.state === state}
              tone={(byState[state] ?? 0) > 0 ? stateTone(state) : "muted"}
            >
              {byState[state] ?? 0} {stateLabel(state)}
            </StripLink>
          ))}
          {otherStates.map(([state, count]) => (
            <StripLink
              key={state}
              href={filterHref(repoId, filters, "state", state)}
              active={filters.state === state}
              tone={stateTone(state)}
            >
              {count} {stateLabel(state)}
            </StripLink>
          ))}
        </div>
        <SeverityStrip
          label="Severity"
          counts={data.counts.by_severity}
          active={filters.severity}
          href={(s) => filterHref(repoId, filters, "severity", s)}
        />
        <SeverityStrip
          label="Effective here"
          counts={data.counts.by_effective_severity}
          active={filters.effective}
          href={(s) => filterHref(repoId, filters, "effective", s)}
        />
        {filtered ? (
          <p className="text-[13px] text-ink-3">
            Showing {data.acceptances.length} of {data.total}.{" "}
            <Link href={`/repos/${repoId}?tab=risk`} className="text-accent hover:underline">
              Clear filters
            </Link>
          </p>
        ) : null}
      </div>

      {data.acceptances.length === 0 ? (
        <EmptyState
          title="No acceptance matches these filters"
          detail={`${data.total} acceptance(s) in this repository; none in this combination.`}
        />
      ) : (
        <ul className="flex flex-col gap-3">
          {data.acceptances.map((row) => (
            <AcceptanceRow key={row.id} repoId={repoId} row={row} />
          ))}
        </ul>
      )}
    </div>
  );
}

function StripLink({
  href,
  active,
  tone,
  children,
}: {
  href: string;
  active: boolean;
  tone: "critical" | "warn" | "pass" | "muted" | "accent";
  children: ReactNode;
}) {
  return (
    <Link
      href={href}
      aria-current={active ? "true" : undefined}
      className={active ? "outline outline-2 outline-offset-1 outline-accent" : "hover:opacity-80"}
    >
      <Pill tone={active ? "accent" : tone}>{children}</Pill>
    </Link>
  );
}

function SeverityStrip({
  label,
  counts,
  active,
  href,
}: {
  label: string;
  counts: Record<string, number>;
  active?: string;
  href: (severity: string) => string;
}) {
  const entries = severityCounts(counts);
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Label>{label}</Label>
      {entries.length === 0 ? (
        <span className="text-[13px] text-ink-3">no covered finding has one</span>
      ) : (
        entries.map(([severity, count]) => (
          <StripLink
            key={severity}
            href={href(severity)}
            active={active === severity}
            tone={severity === "critical" ? "critical" : severity === "high" ? "warn" : "muted"}
          >
            {count} {severity}
          </StripLink>
        ))
      )}
    </div>
  );
}

/** How many covered findings a row lists before "and N more". */
const ROW_FINDINGS_SHOWN = 3;

function AcceptanceRow({ repoId, row }: { repoId: string; row: RiskAcceptanceRow }) {
  const fixable = row.findings.filter((f) => f.now_fixable);
  return (
    <li
      className={`border bg-paper-2 ${row.alarm ? "border-critical" : "border-rule"}`}
      id={`acceptance-${row.id}`}
    >
      <div className="flex flex-wrap items-baseline gap-2 border-b border-rule-soft px-3 py-2">
        <Pill tone={stateTone(row.state)}>{stateLabel(row.state)}</Pill>
        {row.review_due ? <Pill tone="warn">{reviewDueLabel(row)}</Pill> : null}
        <SeverityPair severity={row.severity} effective={row.effective_severity} />
        <span className="text-ink">{reasonLabel(row.reason_code)}</span>
        <span className="text-[13px] text-ink-3">
          {row.findings_total} finding{row.findings_total === 1 ? "" : "s"}
          {row.legacy ? " · migrated" : ""}
          {row.renewal_count ? ` · renewed ${row.renewal_count}x` : ""}
        </span>
        <Link
          href={`/repos/${repoId}/risk/${row.id}`}
          className="ml-auto font-mono text-[12px] text-accent hover:underline"
        >
          Full detail →
        </Link>
      </div>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 px-3 py-2 text-[14px] md:grid-cols-[max-content_1fr]">
        <dt className="text-ink-3">Covers</dt>
        <dd>
          {row.findings.length === 0 ? (
            <span className="text-ink-3">no findings recorded</span>
          ) : (
            <ul className="flex flex-col gap-0.5">
              {row.findings.slice(0, ROW_FINDINGS_SHOWN).map((finding) => (
                <li key={finding.finding_id}>
                  <CoveredFinding repoId={repoId} finding={finding} />
                </li>
              ))}
              {row.findings_total > ROW_FINDINGS_SHOWN ? (
                <li className="text-[13px] text-ink-3">
                  and {row.findings_total - ROW_FINDINGS_SHOWN} more —{" "}
                  <Link
                    href={`/repos/${repoId}/risk/${row.id}#findings`}
                    className="text-accent hover:underline"
                  >
                    see all
                  </Link>
                </li>
              ) : null}
            </ul>
          )}
        </dd>

        <dt className="text-ink-3">Rests on</dt>
        <dd>
          {row.premises.length === 0 ? (
            <span className="text-ink-3">no premise recorded</span>
          ) : (
            <ul className="flex flex-col gap-0.5">
              {row.premises.map((premise) => (
                <li key={premise.index}>
                  <PremiseVerdict
                    type={premise.type}
                    status={premise.status}
                    ageDays={premise.evidence_age_days}
                    reason={premise.reason}
                  />
                </li>
              ))}
            </ul>
          )}
        </dd>

        {row.compensating_controls.length > 0 ? (
          <>
            <dt className="text-ink-3">Controls</dt>
            <dd>
              <ul className="flex flex-col gap-0.5 text-ink-2">
                {row.compensating_controls.map((control, i) => (
                  <li key={i}>{controlText(control)}</li>
                ))}
              </ul>
            </dd>
          </>
        ) : null}

        <dt className="text-ink-3">Expires</dt>
        <dd>
          <Expiry row={row} />
        </dd>

        <dt className="text-ink-3">Owner</dt>
        <dd className="text-ink-2">
          {row.risk_owner || "—"}
          <span className="text-ink-3"> · approved by </span>
          {row.approved_by ?? <span className="text-ink-3">nobody yet</span>}
          <span className="text-ink-3"> · created </span>
          <RelativeTime value={row.created_at} />
        </dd>

        <dt className="text-ink-3">Fix</dt>
        <dd>
          {row.now_fixable > 0 ? (
            <span className="inline-flex flex-wrap items-baseline gap-1.5">
              <FixAvailability nowFixable fixedVersion={fixable[0]?.fixed_version ?? ""} />
              <span className="text-[13px] text-critical">
                {row.now_fixable} covered finding{row.now_fixable === 1 ? " has" : "s have"} a
                fix now
              </span>
            </span>
          ) : (
            <FixAvailability
              nowFixable={false}
              fixedVersion={row.findings.find((f) => f.fixed_version)?.fixed_version ?? ""}
            />
          )}
        </dd>
      </dl>
    </li>
  );
}
