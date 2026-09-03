import Link from "next/link";

import { ControlList } from "@/components/controls";
import { CAPABILITY_META, Pill, Section, SeverityText } from "@/components/primitives";
import type { Severity, ThreatModelCategory, ThreatModelPage } from "@/lib/api";

/**
 * The Threat Model tab (spec 18 §6, spec 28).
 *
 * A STRIDE-categorized attack-surface inventory built entirely from findings
 * and supply-chain evidence already in the lake — not a diagram, not an
 * AI-authored narrative.
 *
 * Two things changed that this file used to state the opposite of.
 * `mapping_resolution` is no longer always "capability": CWEs are read out of
 * SARIF (spec 28 §1) and placed through a reviewed map (§2), so a row says how
 * it was placed and a mixed repository says mixed.
 *
 * And an empty category no longer reads as safe. "Nothing here — not hidden,
 * empty" applied the right instinct to the wrong distinction: a category with
 * no findings because DAST has never run rendered identically to one with no
 * findings because the code is clean. Four states now (spec 28 §4), and
 * `unscanned` is the one that mattered most, because it was the one rendering
 * as good news.
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
  return (
    <div className="flex flex-col gap-4">
      <p className="max-w-prose border-l-2 border-rule bg-paper-2 px-3 py-2 text-[14px] leading-relaxed text-ink-2">
        <strong className="text-ink">Found, and what stops it.</strong> Every
        finding below traces to a real, open row — this is not a diagram or an
        AI-generated narrative. Where the reporting tool declared a CWE, the
        finding is placed by that; where it did not, by the{" "}
        <em>capability</em> that reported it, which is coarser, and each row
        says which of the two it was. Controls are{" "}
        <strong className="text-ink">declared</strong> — a person asserted
        them, and nothing here verifies that they work.
      </p>

      {page.nothing_scanned ? (
        <p className="max-w-prose border-l-2 border-high bg-high-wash px-3 py-2 text-[14px] leading-relaxed text-ink-2">
          <strong className="text-ink">Nothing has scanned this repository.</strong>{" "}
          Every category below is unassessed rather than clean. Said once here
          rather than six times underneath: it is one fact about the
          repository, not six about its categories.
        </p>
      ) : null}

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
                <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-ink-3">
                  {label}
                </div>
                <div className="font-mono text-sm font-bold text-ink">{value}</div>
              </div>
            ))}
          </div>
        </Section>
      ) : null}

      {/* Every category renders whatever its state, including the empty
          ones. An inventory that hides its empty categories cannot
          distinguish "clean" from "nobody looked", which is the distinction
          this whole section exists to make. */}
      {page.categories.map((category) => (
        <StrideCategory key={category.stride} repoId={repoId} category={category} />
      ))}
    </div>
  );
}

const STATE_LABEL: Record<string, string> = {
  findings_open: "findings open",
  unmitigated: "unmitigated",
  mitigated: "mitigated",
  unscanned: "unscanned",
};

const STATE_TONE: Record<string, "critical" | "warn" | "pass" | "muted"> = {
  findings_open: "critical",
  // Not `pass`. Scanned, clean and nothing declared is a fine place to be and
  // is not an achievement — colouring it green would put it level with a
  // category somebody actually built a control for.
  unmitigated: "muted",
  mitigated: "pass",
  // The state that used to render as good news.
  unscanned: "warn",
};

function StrideCategory({
  repoId,
  category,
}: {
  repoId: string;
  category: ThreatModelCategory;
}) {
  const label = STRIDE_LABEL[category.stride] ?? category.stride;
  const state = category.state ?? "findings_open";

  return (
    <Section
      title={label}
      detail={
        category.findings.length === 0
          ? (STATE_LABEL[state] ?? state)
          : `${category.findings.length} item${category.findings.length === 1 ? "" : "s"}`
      }
    >
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1 border-b border-rule-soft px-3 py-1.5">
        <Pill tone={STATE_TONE[state] ?? "muted"}>{STATE_LABEL[state] ?? state}</Pill>
        {/* Shown rather than resolved: a control that exists while findings
            accumulate under it is either wrong, bypassed, or narrower than its
            description, and nothing here can decide which. */}
        {category.contradicted ? <Pill tone="critical">contradicted</Pill> : null}
        <span className="max-w-prose text-[12px] leading-relaxed text-ink-3">
          {category.reason}
        </span>
      </div>

      {category.findings.length === 0 ? null : (
        <div className="scroll-x">
          <table className="w-full min-w-[640px] border-collapse font-mono text-[13px]">
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

      <ControlList
        repoId={repoId}
        stride={category.stride}
        controls={category.controls ?? []}
      />
    </Section>
  );
}
