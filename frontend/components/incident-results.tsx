import Link from "next/link";

import { ErrorPanel, Label, Pill, SeverityText } from "@/components/primitives";
import { RelativeTime } from "@/components/relative-time";
import type { Severity } from "@/lib/api";
import { getIncident } from "@/lib/server";

/**
 * "Are we affected by this?" — the answer, rendered (spec 29 §2).
 *
 * Lifted out of its own page when Incident lookup and Threat intelligence
 * merged. They were always two views of one question: the bands say what the
 * outside world thinks matters, and this says whether it is here. Splitting
 * them meant reading a CVE on one page and retyping it on another.
 *
 * **The layout is built around the answer that could do harm.** "Not affected"
 * is the dangerous one, so the repositories this cannot speak about get their
 * own block with a warning tone and are never folded in with the ones that
 * were genuinely checked and found clean. An inventory that silently omits
 * what it cannot see converts an absence of data into a statement of safety.
 */

const BAND_TONE: Record<string, "pass" | "warn" | "critical"> = {
  go: "pass",
  review_recommended: "warn",
  no_go: "critical",
};

export async function IncidentResults({ query }: { query: string }) {
  const result = await getIncident(query);
  if (!result.ok) {
    return <ErrorPanel title="Lookup failed" detail={result.error} />;
  }
  // Defaulted at the boundary rather than guarded at every use. The fields
  // are optional in the generated types because Pydantic gives them
  // defaults; they are always present in a real response, and threading
  // `?? []` through nine call sites would obscure the one place it matters.
  const view = {
    ...result.data,
    affected: result.data.affected ?? [],
    clear: result.data.clear ?? [],
    not_checked: result.data.not_checked ?? [],
  };

  return (
    <div className="flex flex-col gap-4">
      {view.kind === "cve" ? <Advisory view={view} /> : null}

      <section className="border border-rule bg-paper-2">
        <div className="flex flex-wrap items-baseline gap-x-3 border-b border-rule-soft px-3 py-2">
          <Label>Affected</Label>
          <span className="font-mono text-[10px] text-ink-3">
            {view.affected.length === 0
              ? "no repository in the inventory contains it"
              : `${view.affected.length} repositor${view.affected.length === 1 ? "y" : "ies"} · worst first`}
          </span>
        </div>

        {view.affected.length === 0 ? (
          <p className="px-3 py-2 text-[11px] text-ink-3">
            Nothing matched. Read that together with the block below: it means
            nothing matched <em>among the repositories this can see</em>.
          </p>
        ) : (
          <div className="scroll-x">
            <table className="w-full min-w-[720px] border-collapse font-mono text-[11px]">
              <tbody>
                {view.affected.map((item) => (
                  <tr
                    key={item.repo_full_name}
                    className="border-t border-rule-soft first:border-t-0 align-baseline"
                  >
                    <td className="px-2 py-1.5">
                      {item.repo_id ? (
                        <Link
                          href={`/repos/${encodeURIComponent(item.repo_id)}?tab=sscs`}
                          className="font-semibold text-ink hover:text-accent"
                        >
                          {item.repo_full_name}
                        </Link>
                      ) : (
                        <span className="font-semibold text-ink">
                          {item.repo_full_name}
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-1.5 text-ink-2">
                      {(item.versions ?? []).join(", ") || "version not recorded"}
                    </td>
                    <td className="px-2 py-1.5">
                      {item.open_findings > 0 ? (
                        <span className="flex items-baseline gap-1.5">
                          <SeverityText severity={item.highest_severity as Severity} />
                          <span className="text-ink-3">
                            {item.open_findings} open
                          </span>
                        </span>
                      ) : (
                        // Exposure and a finding are different facts: a
                        // repository can contain a vulnerable package with no
                        // finding, because its last scan predates the
                        // advisory. Saying "present, no finding" is the honest
                        // rendering of that; a blank cell would read as safe.
                        <span className="text-ink-3">present, no finding</span>
                      )}
                    </td>
                    <td className="px-2 py-1.5 text-ink-2">
                      {item.fixed_version ? `fix: ${item.fixed_version}` : ""}
                    </td>
                    <td className="px-2 py-1.5">
                      {item.recommendation ? (
                        <Pill tone={BAND_TONE[item.recommendation] ?? "muted"}>
                          {item.recommendation.replace(/_/g, " ")}
                        </Pill>
                      ) : null}
                    </td>
                    <td className="px-2 py-1.5 text-[10px] text-ink-3">
                      {/* As of when, on every row. Stale data presented as
                          current is the other way this page could mislead
                          somebody who is in a hurry. */}
                      {item.observed_at ? (
                        <>
                          as of <RelativeTime value={item.observed_at} />
                        </>
                      ) : null}
                      {item.matched_by === "name" ? (
                        <span
                          className="ml-1.5"
                          title="Matched on package name rather than purl — usually right, and a guess."
                        >
                          (by name)
                        </span>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* The block this page exists to make impossible to miss. */}
      {view.not_checked.length > 0 ? (
        <section className="border border-high bg-high-wash">
          <div className="border-b border-high/40 px-3 py-2">
            <Label>Not checked — {view.not_checked.length}</Label>
          </div>
          <p className="max-w-prose px-3 py-2 text-[11px] leading-relaxed text-ink-2">
            <strong className="text-ink">These are not a clean result.</strong>{" "}
            No SBOM has reached the lake for them, so this page cannot say
            whether they contain it. Enable Atlas, or check them by hand before
            standing down.
          </p>
          <ul className="flex flex-wrap gap-x-3 gap-y-1 px-3 pb-2 font-mono text-[11px] text-ink-2">
            {view.not_checked.map((name) => (
              <li key={name}>{name}</li>
            ))}
          </ul>
        </section>
      ) : null}

      {view.clear.length > 0 ? (
        <section className="border border-rule bg-paper-2">
          <div className="border-b border-rule-soft px-3 py-2">
            <Label>Checked and clear — {view.clear.length}</Label>
          </div>
          <ul className="flex flex-wrap gap-x-3 gap-y-1 px-3 py-2 font-mono text-[11px] text-ink-3">
            {view.clear.map((name) => (
              <li key={name}>{name}</li>
            ))}
          </ul>
        </section>
      ) : null}

      <p className="max-w-prose text-[10px] leading-relaxed text-ink-3">{view.note}</p>
    </div>
  );
}

function Advisory({
  view,
}: {
  view: { in_kev?: boolean | null; epss_score?: number | null; query: string };
}) {
  // Null is not false. A CVE the threat-intel job has not seen is one nobody
  // has checked against KEV, and rendering that as "not exploited" is the
  // same error as calling an unscanned repository clean.
  if (view.in_kev == null && view.epss_score == null) {
    return (
      <p className="border-l-2 border-rule bg-paper-2 px-3 py-2 text-[11px] text-ink-3">
        No threat intelligence recorded for {view.query} — it has not been
        checked against KEV, which is not the same as not being listed.
      </p>
    );
  }

  return (
    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-l-2 border-rule bg-paper-2 px-3 py-2">
      <span className="font-mono text-[11px] font-semibold text-ink">
        {view.query}
      </span>
      {view.in_kev ? (
        <Pill tone="critical">in CISA KEV — exploited now</Pill>
      ) : (
        <Pill tone="muted">not in KEV</Pill>
      )}
      {view.epss_score != null ? (
        <span className="font-mono text-[10px] text-ink-2">
          EPSS {view.epss_score.toFixed(2)} — probability of exploitation in 30
          days
        </span>
      ) : null}
    </div>
  );
}
