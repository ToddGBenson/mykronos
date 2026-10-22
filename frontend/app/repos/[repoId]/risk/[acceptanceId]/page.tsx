import Link from "next/link";
import type { ReactNode } from "react";

import {
  CoveredFinding,
  Expiry,
  FixAvailability,
  PremiseVerdict,
  SeverityPair,
} from "@/components/accepted-risk";
import { Crumb, ErrorPanel, Label, Pill, RelativeTime } from "@/components/primitives";
import {
  auditActionLabel,
  controlText,
  interimReviewText,
  premiseTally,
  reasonLabel,
  reviewDueLabel,
  stateLabel,
  stateTone,
} from "@/lib/risk-acceptances";
import { getRepoRiskAcceptance } from "@/lib/server";

export const dynamic = "force-dynamic";

export const metadata = { title: "Risk acceptance — Mykronos" };

/**
 * One risk acceptance, in full: why it was accepted, what it rests on and the
 * evidence for each premise as the monitor reads it now, the covered
 * findings' scores before and after the environment is applied, and every
 * lifecycle event the audit log holds.
 *
 * A sub-route rather than an expanding row, the pattern finding records use:
 * an acceptance can cover thousands of findings and carry several premises
 * with their observations, which is a page, not a disclosure.
 *
 * **No buttons.** The acceptance API can renew and revoke, but no page in this
 * dashboard calls those routes yet; the actions are listed with their routes
 * so an operator (or the agent playbook, which offers the same ones) can take
 * them, rather than this page inventing a mutation path of its own.
 */
export default async function RiskAcceptancePage({
  params,
}: {
  params: Promise<{ repoId: string; acceptanceId: string }>;
}) {
  const { repoId, acceptanceId } = await params;
  const result = await getRepoRiskAcceptance(repoId, acceptanceId);
  if (!result.ok) {
    return <ErrorPanel title="Risk acceptance unavailable" detail={result.error} />;
  }
  const a = result.data;
  const tally = premiseTally(a.premises);

  return (
    <div className="flex flex-col gap-4">
      <div className="font-mono text-[12px] text-ink-3">
        <Crumb href="/">Portfolio</Crumb> /{" "}
        <Crumb href={`/repos/${repoId}`}>{a.repo_full_name}</Crumb> /{" "}
        <Crumb href={`/repos/${repoId}?tab=risk`}>Risk management</Crumb> /{" "}
        <span className="text-ink-2">{a.id.slice(0, 8)}</span>
      </div>

      <header className="flex flex-col gap-1.5">
        <div className="flex flex-wrap items-baseline gap-2">
          <Pill tone={stateTone(a.state)}>{stateLabel(a.state)}</Pill>
          {a.review_due ? <Pill tone="warn">{reviewDueLabel(a)}</Pill> : null}
          <SeverityPair severity={a.severity} effective={a.effective_severity} />
          {a.legacy ? <Pill tone="muted">migrated</Pill> : null}
        </div>
        <h1 className="max-w-4xl text-xl font-semibold leading-snug">
          {reasonLabel(a.reason_code)}: {a.findings_total} finding
          {a.findings_total === 1 ? "" : "s"} accepted
        </h1>
        <p className="font-mono text-[12px] text-ink-3">
          {a.deviation_type.replaceAll("_", " ") || "no deviation type"} · response{" "}
          {a.response} · premises: {tally.holds} hold, {tally.unverified} unverified,{" "}
          {tally.failed} failed
        </p>
      </header>

      <Block title="Decision">
        <dl className="grid grid-cols-1 gap-x-6 gap-y-1.5 text-[14px] md:grid-cols-[max-content_1fr]">
          <Field label="Risk owner">{a.risk_owner || "—"}</Field>
          <Field label="Requested by">{a.requested_by || "—"}</Field>
          <Field label="Approved by">
            {a.approved_by ?? <span className="text-ink-3">nobody yet</span>}
            {a.approval_request_id ? (
              <span className="font-mono text-[12px] text-ink-3">
                {" "}
                · approval request {a.approval_request_id.slice(0, 8)}
              </span>
            ) : null}
          </Field>
          <Field label="Residual risk">
            {a.residual_severity || "—"}
            <span className="text-ink-3">
              {" "}
              (likelihood {a.residual_likelihood || "—"} × impact {a.residual_impact || "—"})
            </span>
          </Field>
          <Field label="Created">
            {a.created_at.slice(0, 10)} <RelativeTime value={a.created_at} />
          </Field>
          <Field label="Effective">{a.effective_at ? a.effective_at.slice(0, 10) : "—"}</Field>
          <Field label="Review by">{a.review_by ?? "—"}</Field>
          {interimReviewText(a) ? (
            <Field label="Interim review">
              {interimReviewText(a)}
              <span className="text-ink-3"> — nothing watches this reason, so a person looks again</span>
            </Field>
          ) : null}
          <Field label="Expires">
            <Expiry row={a} />
          </Field>
          {a.tracking_ref ? <Field label="Tracking">{a.tracking_ref}</Field> : null}
          {a.renews_id ? (
            <Field label="Renews">
              <Link href={`/repos/${repoId}/risk/${a.renews_id}`} className="text-accent hover:underline">
                {a.renews_id.slice(0, 8)}
              </Link>
            </Field>
          ) : null}
          {a.renewed_by.length > 0 ? (
            <Field label="Renewed by">
              {a.renewed_by.map((id, i) => (
                <span key={id}>
                  {i > 0 ? ", " : ""}
                  <Link href={`/repos/${repoId}/risk/${id}`} className="text-accent hover:underline">
                    {id.slice(0, 8)}
                  </Link>
                </span>
              ))}
            </Field>
          ) : null}
          {a.closed_at ? (
            <Field label="Closed">
              {a.closed_at.slice(0, 10)}
              {a.closed_reason ? <span className="text-ink-3"> — {a.closed_reason}</span> : null}
            </Field>
          ) : null}
        </dl>
      </Block>

      <Block title="Justification">
        <p className="max-w-prose whitespace-pre-wrap text-[14px] leading-relaxed text-ink-2">
          {a.justification || "No justification recorded."}
        </p>
      </Block>

      <Block
        title="What it rests on"
        detail={`as the premise monitor reads it now · fresh = collected within ${a.premise_fresh_days} days`}
      >
        {a.premises.length === 0 ? (
          <p className="text-[14px] text-ink-3">No premise recorded.</p>
        ) : (
          <ul className="flex flex-col gap-3">
            {a.premises.map((premise) => (
              <li key={premise.index} className="flex flex-col gap-1 border-t border-rule-soft pt-2">
                <PremiseVerdict
                  type={premise.type}
                  status={premise.status}
                  ageDays={premise.evidence_age_days}
                />
                <p className="max-w-prose text-[13px] leading-relaxed text-ink-2">
                  {premise.reason}
                </p>
                <PremiseKeys premise={premise.premise} />
                {premise.evidence.length > 0 ? (
                  <div className="scroll-x">
                    <table className="w-full min-w-[720px] border-collapse font-mono text-[12px]">
                      <thead>
                        <tr className="text-left text-ink-3">
                          <th className="px-2 py-1 font-normal">Observed</th>
                          <th className="px-2 py-1 font-normal">Subject</th>
                          <th className="px-2 py-1 font-normal">Assertion</th>
                          <th className="px-2 py-1 font-normal">Vantage</th>
                          <th className="px-2 py-1 font-normal">State</th>
                          <th className="px-2 py-1 font-normal">Collector</th>
                        </tr>
                      </thead>
                      <tbody>
                        {premise.evidence.map((e, i) => (
                          <EvidenceRow key={i} evidence={e} />
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-[13px] text-ink-3">No evidence behind this verdict.</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </Block>

      {a.compensating_controls.length > 0 || a.milestones.length > 0 ? (
        <Block title="Controls and milestones">
          {a.compensating_controls.length > 0 ? (
            <>
              <Label>Compensating controls</Label>
              <ul className="mb-2 ml-4 list-disc text-[14px] text-ink-2">
                {a.compensating_controls.map((c, i) => (
                  <li key={i}>{controlText(c)}</li>
                ))}
              </ul>
            </>
          ) : null}
          {a.milestones.length > 0 ? (
            <>
              <Label>Milestones</Label>
              <ul className="ml-4 list-disc text-[14px] text-ink-2">
                {a.milestones.map((m, i) => (
                  <li key={i}>{controlText(m)}</li>
                ))}
              </ul>
            </>
          ) : null}
        </Block>
      ) : null}

      <Block
        title="Findings covered"
        id="findings"
        detail={
          a.findings.length < a.findings_total
            ? `${a.findings.length} of ${a.findings_total} shown, worst first`
            : `${a.findings_total}, worst first`
        }
      >
        {a.findings.length === 0 ? (
          <p className="text-[14px] text-ink-3">No findings recorded.</p>
        ) : (
          <ul className="flex flex-col gap-1 text-[14px]">
            {a.findings.map((f) => (
              <li key={f.finding_id} className="flex flex-wrap items-baseline gap-2">
                <CoveredFinding repoId={repoId} finding={f} />
                {f.status !== "missing" ? (
                  <FixAvailability nowFixable={f.now_fixable} fixedVersion={f.fixed_version} />
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </Block>

      <Block
        title="Environmental score"
        detail={`base → environmental · ${a.scores.scored} of ${a.scores.shown} shown scored, ${a.scores.total} covered`}
      >
        {a.scores.items.length === 0 ? (
          <p className="text-[14px] text-ink-3">{a.scores.reason}</p>
        ) : (
          <div className="scroll-x">
            <table className="w-full min-w-[720px] border-collapse font-mono text-[12px]">
              <thead>
                <tr className="text-left text-ink-3">
                  <th className="px-2 py-1 font-normal">Finding</th>
                  <th className="px-2 py-1 font-normal">Before</th>
                  <th className="px-2 py-1 font-normal">After</th>
                  <th className="px-2 py-1 font-normal">Severity</th>
                  <th className="px-2 py-1 font-normal">Vector</th>
                  <th className="px-2 py-1 font-normal">Computed</th>
                </tr>
              </thead>
              <tbody>
                {a.scores.items.map((s) => (
                  <tr key={s.finding_id} className="border-t border-rule-soft align-baseline">
                    <td className="px-2 py-1">
                      <Link
                        href={`/repos/${repoId}/findings/${s.finding_id}`}
                        className="text-accent hover:underline"
                      >
                        {s.finding_id.slice(0, 12)}
                      </Link>
                    </td>
                    <td className="px-2 py-1 text-ink-2">
                      {s.base.toFixed(1)} {s.base_band}
                    </td>
                    <td className="px-2 py-1 text-ink">
                      {s.environmental.toFixed(1)} {s.env_band}
                    </td>
                    <td className="px-2 py-1">
                      <SeverityPair severity={s.scanner_severity} effective={s.effective_severity} />
                    </td>
                    <td className="max-w-[40ch] truncate px-2 py-1 text-ink-3" title={s.vector}>
                      {s.vector} ({s.vector_source})
                    </td>
                    <td className="px-2 py-1 text-ink-3">
                      <RelativeTime value={s.computed_at} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Block>

      <Block title="History" detail="from the audit log">
        {a.history.length === 0 ? (
          <p className="text-[14px] text-ink-3">No audit entries for this acceptance.</p>
        ) : (
          <ol className="flex flex-col gap-1 text-[14px]">
            {a.history.map((event, i) => (
              <li key={i} className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono text-[12px] text-ink-3">
                  {event.at.slice(0, 16).replace("T", " ")}
                </span>
                <span
                  className={
                    event.action.endsWith("premise_failed") || event.action.endsWith("revoked")
                      ? "font-semibold text-critical"
                      : "text-ink"
                  }
                >
                  {auditActionLabel(event.action)}
                </span>
                <span className="text-[13px] text-ink-3">
                  by {event.actor}
                  {event.actor_kind ? ` (${event.actor_kind})` : ""}
                </span>
                <HistoryDetail detail={event.detail} />
              </li>
            ))}
          </ol>
        )}
      </Block>

      <Block title="Actions" detail="offered by the acceptance API for this record's status">
        {a.actions.length === 0 ? (
          <p className="text-[14px] text-ink-3">
            None: a {stateLabel(a.state).toLowerCase()} acceptance cannot be renewed or revoked.
          </p>
        ) : (
          <>
            <ul className="flex flex-col gap-1.5 text-[14px]">
              {a.actions.map((action) => (
                <li key={action.label} className="flex flex-col">
                  <span>
                    <strong>{action.label}</strong>{" "}
                    <span className="font-mono text-[12px] text-ink-3">
                      {action.method} {action.path} · {action.who}
                    </span>
                  </span>
                  <span className="text-[13px] text-ink-2">{action.effect}</span>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[13px] text-ink-3">
              Not buttons yet: no page in this dashboard calls these routes. The agent work
              queue offers the same actions.
            </p>
          </>
        )}
      </Block>

      <details className="border border-rule bg-paper-2 px-3 py-2">
        <summary className="cursor-pointer font-mono text-[12px] text-ink-3">
          Scope predicate (what chose the findings)
        </summary>
        <pre className="mt-2 overflow-x-auto font-mono text-[12px] text-ink-2">
          {JSON.stringify(a.scope, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function Block({
  title,
  detail,
  id,
  children,
}: {
  title: string;
  detail?: string;
  id?: string;
  children: ReactNode;
}) {
  return (
    <section id={id} className="border border-rule bg-paper-2">
      <div className="flex flex-wrap items-baseline gap-x-3 border-b border-rule-soft px-3 py-1.5">
        <Label as="h2">{title}</Label>
        {detail ? <span className="font-mono text-[12px] text-ink-3">{detail}</span> : null}
      </div>
      <div className="px-3 py-2.5">{children}</div>
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-ink-3">{label}</dt>
      <dd className="text-ink-2">{children}</dd>
    </>
  );
}

function PremiseKeys({ premise }: { premise: Record<string, unknown> }) {
  const keys = Object.entries(premise).filter(([key]) => key !== "type");
  if (keys.length === 0) return null;
  return (
    <p className="font-mono text-[12px] text-ink-3">
      {keys
        .map(([key, value]) => `${key}=${typeof value === "string" ? value : JSON.stringify(value)}`)
        .join(" · ")}
    </p>
  );
}

function text(value: unknown): string {
  return value === undefined || value === null ? "" : String(value);
}

function EvidenceRow({ evidence }: { evidence: Record<string, unknown> }) {
  // An EPSS premise's evidence is a threat-intel row, not an observation.
  if (evidence.source === "threat_intel") {
    return (
      <tr className="border-t border-rule-soft align-baseline">
        <td className="px-2 py-1 text-ink-3">
          <RelativeTime value={text(evidence.fetched_at)} />
        </td>
        <td className="px-2 py-1">{text(evidence.cve)}</td>
        <td className="px-2 py-1">
          EPSS {text(evidence.epss)} vs {text(evidence.threshold)}
        </td>
        <td className="px-2 py-1 text-ink-3">—</td>
        <td className="px-2 py-1 text-ink-3">—</td>
        <td className="px-2 py-1 text-ink-3">threat intel</td>
      </tr>
    );
  }
  return (
    <tr className="border-t border-rule-soft align-baseline" title={text(evidence.detail)}>
      <td className="px-2 py-1 text-ink-3">
        <RelativeTime value={text(evidence.collected_at)} />
        {evidence.fresh === false ? <span className="text-high"> stale</span> : null}
      </td>
      <td className="px-2 py-1">{text(evidence.subject)}</td>
      <td className="px-2 py-1">{text(evidence.assertion)}</td>
      <td className="px-2 py-1">{text(evidence.vantage)}</td>
      <td className="px-2 py-1">{text(evidence.state)}</td>
      <td className="px-2 py-1 text-ink-3">
        {text(evidence.collector) || "—"}
        {evidence.tool ? ` · ${text(evidence.tool)}` : ""}
      </td>
    </tr>
  );
}

/** The few detail keys worth a reader's eye, not the whole JSON. */
function HistoryDetail({ detail }: { detail: Record<string, unknown> }) {
  const parts: string[] = [];
  if (detail.reason) parts.push(text(detail.reason));
  if (detail.findings_reopened !== undefined) parts.push(`${text(detail.findings_reopened)} reopened`);
  if (detail.findings !== undefined) parts.push(`${text(detail.findings)} findings`);
  if (Array.isArray(detail.failed)) {
    parts.push(
      "failed: " +
        detail.failed
          .map((f) => (f && typeof f === "object" ? text((f as Record<string, unknown>).type) : ""))
          .filter(Boolean)
          .join(", "),
    );
  }
  if (Array.isArray(detail.observation_ids) && detail.observation_ids.length > 0) {
    parts.push(`observations ${detail.observation_ids.map(text).join(", ")}`);
  }
  if (detail.count !== undefined) parts.push(`${text(detail.count)} drifted`);
  if (parts.length === 0) return null;
  return <span className="text-[13px] text-ink-2">— {parts.join(" · ")}</span>;
}
