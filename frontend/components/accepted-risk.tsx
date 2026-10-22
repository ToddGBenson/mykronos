import Link from "next/link";

import { Pill, SeverityText } from "@/components/primitives";
import type { Severity } from "@/lib/api";
import {
  daysLeftText,
  evidenceAgeText,
  expiryIsRed,
  premiseLabel,
  verdictTone,
} from "@/lib/risk-acceptances";

/**
 * Pieces of accepted risk that render the same wherever an acceptance is
 * shown: the estate-wide list on Vulnerability management and the
 * repository's Risk management tab.
 */

/** Whether a fix exists now. Accepted for want of one and one shipped: red. */
export function FixAvailability({
  nowFixable,
  fixedVersion,
}: {
  nowFixable: boolean;
  fixedVersion: string;
}) {
  if (nowFixable) return <Pill tone="critical">{fixedVersion} available</Pill>;
  if (fixedVersion) return <span className="text-ink-3">{fixedVersion}</span>;
  return <span className="text-ink-3">none published</span>;
}

/** Scanner severity, and the environmental one beside it when it differs. */
export function SeverityPair({
  severity,
  effective,
}: {
  severity: string;
  effective: string;
}) {
  if (!severity && !effective) return <span className="text-ink-3">—</span>;
  return (
    <span className="inline-flex items-baseline gap-1">
      {severity ? <SeverityText severity={severity as Severity} /> : null}
      {effective && effective !== severity ? (
        <>
          <span className="text-ink-3" aria-label="re-read here as">
            →
          </span>
          <SeverityText severity={effective as Severity} />
          <span className="text-[11px] text-ink-3">here</span>
        </>
      ) : null}
    </span>
  );
}

/** One premise: what it asserts, the monitor's verdict today, and how old the evidence is. */
export function PremiseVerdict({
  type,
  status,
  ageDays,
  reason,
}: {
  type: string;
  status: string;
  ageDays?: number | null;
  reason?: string;
}) {
  return (
    <span className="inline-flex flex-wrap items-baseline gap-1.5" title={reason}>
      <span className="text-ink-2">{premiseLabel(type)}</span>
      <Pill tone={verdictTone(status)}>{status}</Pill>
      <span className="text-[12px] text-ink-3">{evidenceAgeText(ageDays)}</span>
    </span>
  );
}

/** The expiry date and the days left, red when past or a premise has failed. */
export function Expiry({
  row,
}: {
  row: {
    expires_at?: string | null;
    days_left?: number | null;
    state: string;
    premises: readonly { status: string }[];
  };
}) {
  const red = expiryIsRed(row);
  return (
    <span className={red ? "font-bold text-critical" : "text-ink-2"}>
      {row.expires_at ?? "—"}{" "}
      <span className={red ? "" : "text-ink-3"}>({daysLeftText(row.days_left)})</span>
    </span>
  );
}

/** A covered finding: severity pair, title, rule, linked to its record page. */
export function CoveredFinding({
  repoId,
  finding,
}: {
  repoId: string;
  finding: {
    finding_id: string;
    title: string;
    rule_id: string;
    severity: string;
    effective_severity: string;
    status: string;
    package_name: string;
    /** The host, for a network finding (TheHub #60813). */
    asset?: string;
  };
}) {
  if (finding.status === "missing") {
    return (
      <span className="text-ink-3">
        {finding.finding_id.slice(0, 12)} — no longer in this repository&apos;s findings
      </span>
    );
  }
  return (
    <span className="inline-flex flex-wrap items-baseline gap-1.5">
      <SeverityPair severity={finding.severity} effective={finding.effective_severity} />
      <Link
        href={`/repos/${repoId}/findings/${finding.finding_id}`}
        className="text-ink hover:text-accent hover:underline"
      >
        {finding.title || finding.rule_id || finding.finding_id}
      </Link>
      <span className="font-mono text-[12px] text-ink-3">
        {finding.rule_id}
        {finding.package_name ? ` · ${finding.package_name}` : ""}
        {finding.asset ? ` · host ${finding.asset}` : ""}
        {finding.status && finding.status !== "accepted_risk" ? ` · ${finding.status}` : ""}
      </span>
    </span>
  );
}
