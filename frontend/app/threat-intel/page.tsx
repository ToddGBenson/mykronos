import Link from "next/link";

import {
  EmptyState,
  ErrorPanel,
  Label,
  Pill,
  RelativeTime,
  SeverityText,
} from "@/components/primitives";
import type { Severity } from "@/lib/api";
import { getThreatIntel } from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * Which of our findings does the outside world currently think matters most
 * (spec 17 §4.4) — a different question, and a different ordering, from the
 * Triage queue's severity-then-age. KEV is a fact ("known exploited");
 * EPSS is a probability that moves day to day. Neither is Oracle's score,
 * and this page does not try to be — it is the input the queue doesn't have.
 */
export default async function ThreatIntelPage() {
  const result = await getThreatIntel();
  if (!result.ok) {
    return <ErrorPanel title="Threat intelligence unavailable" detail={result.error} />;
  }

  const entries = result.data;
  const kevCount = entries.filter((e) => e.in_kev).length;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Threat intelligence</h1>
        <span className="font-mono text-[11px] text-ink-3">
          {entries.length} CVE{entries.length === 1 ? "" : "s"} matched to open findings
          {kevCount > 0 ? ` · ${kevCount} in CISA KEV` : ""}
        </span>
        <Link
          href="/triage"
          className="ml-auto border border-rule px-2 py-1 font-mono text-[10px] text-ink-3 hover:border-accent hover:text-accent"
        >
          triage queue
        </Link>
      </div>

      {entries.length === 0 ? (
        <EmptyState
          title="Nothing to show yet"
          detail={
            <>
              Either no open finding names a CVE (most SAST/IaC findings
              describe a code pattern, not a published vulnerability), or the
              daily KEV/EPSS refresh hasn&rsquo;t run yet. Findings that do
              name a CVE appear here immediately, before the refresh — with an
              honest &ldquo;not yet fetched&rdquo; rather than nothing.
            </>
          }
        />
      ) : (
        <div className="scroll-x border border-rule">
          <table className="w-full min-w-[760px] border-collapse bg-paper-2 font-mono text-[11px]">
            <thead>
              <tr className="border-b-2 border-ink-2 text-left">
                {["", "CVE", "Worst sev.", "EPSS", "Repos", "Findings", "Fetched"].map(
                  (heading) => (
                    <th
                      key={heading}
                      className="whitespace-nowrap px-2 py-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-ink-3"
                    >
                      {heading}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr
                  key={entry.cve_id}
                  className={`border-b border-rule-soft last:border-b-0 hover:bg-paper-3 ${
                    entry.in_kev ? "border-l-2 border-l-critical" : ""
                  }`}
                >
                  <td className="px-2 py-2">
                    {entry.in_kev ? <Pill tone="critical">KEV</Pill> : null}
                  </td>
                  <td className="px-2 py-2">
                    <Link
                      href={`/triage?rule_id=${encodeURIComponent(entry.cve_id)}`}
                      className="font-semibold text-ink hover:text-accent"
                    >
                      {entry.cve_id}
                    </Link>
                    {entry.in_kev && entry.kev_added_at ? (
                      <div className="text-[9px] text-ink-3">
                        added to KEV <RelativeTime value={entry.kev_added_at} />
                      </div>
                    ) : null}
                  </td>
                  <td className="px-2 py-2">
                    <SeverityText severity={entry.worst_severity as Severity} />
                  </td>
                  <td className="tabular px-2 py-2">
                    {typeof entry.epss_score === "number" ? (
                      <span className={entry.epss_score >= 0.5 ? "font-bold text-high" : ""}>
                        {(entry.epss_score * 100).toFixed(1)}%
                      </span>
                    ) : (
                      <span className="text-ink-3" title="Not yet fetched, or not scored">
                        —
                      </span>
                    )}
                  </td>
                  <td className="max-w-[24ch] truncate px-2 py-2 text-ink-2">
                    {entry.repo_full_names.join(", ")}
                  </td>
                  <td className="tabular px-2 py-2 text-ink-2">{entry.finding_count}</td>
                  <td className="whitespace-nowrap px-2 py-2 text-ink-3">
                    {entry.fetched_at ? (
                      <RelativeTime value={entry.fetched_at} />
                    ) : (
                      <span title="The daily refresh job hasn't run for this CVE yet">
                        not yet fetched
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
        <Label>Reading this list</Label>
        <br />
        Ordered by CISA KEV membership first, then by EPSS descending — a fact
        (&ldquo;known exploited&rdquo;) outranks a probability. Only findings
        with a CVE appear: most SAST and IaC findings describe a code pattern
        rather than a published vulnerability, and there is no equivalent
        public feed for those — inventing one would be a confidence this page
        does not have. A dash under EPSS means not yet scored or not yet
        fetched, never &ldquo;zero risk&rdquo;.
      </p>
    </div>
  );
}
