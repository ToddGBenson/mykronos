import Link from "next/link";

import { CAPABILITY_META, EmptyState, Section, SeverityText } from "@/components/primitives";
import type { Severity, ThreatModelCategory, ThreatModelPage } from "@/lib/api";

/**
 * The Threat Model tab (spec 18 §6).
 *
 * A STRIDE-categorized attack-surface inventory built entirely from findings
 * and supply-chain evidence already in the lake — not a diagram, not an
 * AI-authored narrative. `mapping_resolution` is always "capability" today:
 * no `Finding` carries a structured CWE, so the backend maps a finding's
 * *capability* to the STRIDE categories it can speak to rather than claiming
 * a per-rule precision this data does not support. Said here, not hidden —
 * the same posture the KEV/EPSS badges took with `fetched_at` (spec 17 §4.4).
 */
const STRIDE_LABEL: Record<string, string> = {
  spoofing: "Spoofing",
  tampering: "Tampering",
  repudiation: "Repudiation",
  information_disclosure: "Information Disclosure",
  denial_of_service: "Denial of Service",
  elevation_of_privilege: "Elevation of Privilege",
};

export function ThreatModelTab({
  repoId,
  page,
}: {
  repoId: string;
  page: ThreatModelPage;
}) {
  const totalFindings = page.categories.reduce((sum, c) => sum + c.findings.length, 0);

  return (
    <div className="flex flex-col gap-4">
      <p className="max-w-prose border-l-2 border-rule bg-paper-2 px-3 py-2 text-[11px] leading-relaxed text-ink-2">
        <strong className="text-ink">Capability-level mapping.</strong> Every row below
        traces to a real, open finding — this is not a diagram or an AI-generated
        narrative. But no finding here carries a structured CWE, so a finding is placed
        by which <em>capability</em> reported it (a DAST finding can speak to Spoofing
        and Tampering both), not by a per-rule analysis a CWE taxonomy would support. A
        SQL-injection SAST finding and a hardcoded-credential SAST finding land in the
        same two categories today for that reason.
      </p>

      {page.supply_chain ? (
        <Section
          title="Supply-chain context"
          detail="the dependency graph as a whole, not just its vulnerable slice"
        >
          <div className="grid grid-cols-3 gap-px bg-rule-soft">
            {[
              ["Trust score", page.supply_chain.trust_score ?? "not assessed"],
              ["Dependencies", page.supply_chain.dependency_count],
              ["Vulnerable", page.supply_chain.vulnerable_dependency_count],
            ].map(([label, value]) => (
              <div key={label as string} className="bg-paper-2 px-3 py-2">
                <div className="font-mono text-[9px] uppercase tracking-[0.1em] text-ink-3">
                  {label}
                </div>
                <div className="font-mono text-sm font-bold text-ink">{value}</div>
              </div>
            ))}
          </div>
        </Section>
      ) : null}

      {totalFindings === 0 ? (
        <EmptyState
          title="No attack-surface findings observed"
          detail="Nothing open in dast, network, cloud, iac, secrets, sast, containers, or atlas — the capabilities this inventory is derived from."
        />
      ) : (
        page.categories.map((category) => (
          <StrideCategory key={category.stride} repoId={repoId} category={category} />
        ))
      )}
    </div>
  );
}

function StrideCategory({
  repoId,
  category,
}: {
  repoId: string;
  category: ThreatModelCategory;
}) {
  const label = STRIDE_LABEL[category.stride] ?? category.stride;

  return (
    <Section
      title={label}
      detail={
        category.findings.length === 0
          ? "no findings observed in the capabilities this category is derived from"
          : `${category.findings.length} item${category.findings.length === 1 ? "" : "s"}`
      }
    >
      {category.findings.length === 0 ? (
        <p className="px-3 py-2 text-[11px] text-ink-3">Nothing here — not hidden, empty.</p>
      ) : (
        <div className="scroll-x">
          <table className="w-full min-w-[640px] border-collapse font-mono text-[11px]">
            <tbody>
              {category.findings.map((finding) => (
                <tr
                  key={finding.group_key}
                  className="border-t border-rule-soft first:border-t-0 hover:bg-paper-3"
                >
                  <td className="px-2 py-1.5">
                    <SeverityText severity={finding.severity as Severity} />
                  </td>
                  <td className="px-2 py-1.5">
                    <Link
                      href={`/repos/${repoId}?tab=findings&finding=${finding.locations[0]?.finding_id ?? ""}`}
                      className="font-semibold text-ink hover:text-accent"
                      title={finding.title}
                    >
                      {finding.rule_id}
                    </Link>
                  </td>
                  <td className="px-2 py-1.5 text-ink-3">
                    {finding.capabilities
                      .map((c) => CAPABILITY_META[c as keyof typeof CAPABILITY_META]?.icon ?? c)
                      .join(" ")}
                  </td>
                  <td className="px-2 py-1.5 text-ink-2">
                    {finding.occurrences} occurrence{finding.occurrences === 1 ? "" : "s"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}
