import Link from "next/link";

import {
  EmptyState,
  ErrorPanel,
  Label,
  RelativeTime,
  SeverityText,
} from "@/components/primitives";
import type { Severity, ThreatIntelEntry } from "@/lib/api";
import { getThreatIntel } from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * Which of our findings does the outside world currently think matters most
 * (spec 17 §4.4) — a different question, and a different ordering, from the
 * Triage queue's severity-then-age. KEV is a fact ("known exploited");
 * EPSS is a probability that moves day to day. Neither is Oracle's score,
 * and this page does not try to be — it is the input the queue doesn't have.
 *
 * **Banded rather than flat.** The page used to be one seven-column table with
 * KEV and EPSS in adjacent columns, which gave a binary fact and a continuous
 * probability the same visual weight and left the reader to do the sorting the
 * page had already done. The bands below *are* the decision: something
 * exploited in the wild today is a different kind of thing from something with
 * a 60% chance of exploitation this month, and both are different from a CVE
 * nobody has scored yet.
 *
 * Unscored is its own band for the reason the old dash tried to carry in a
 * tooltip: "not yet fetched" is not "low risk", and burying it at the bottom
 * of an EPSS-descending list made it read as exactly that.
 */
export const metadata = { title: "Threat intelligence — Mykronos" };

/** EPSS at or above this is treated as its own band. CISA's own guidance puts
 *  remediation prioritisation around here, and it is the threshold the old
 *  table already bolded — made structural rather than typographic. */
const LIKELY = 0.5;

export default async function ThreatIntelPage() {
  const result = await getThreatIntel();
  if (!result.ok) {
    return <ErrorPanel title="Threat intelligence unavailable" detail={result.error} />;
  }

  const entries = result.data;

  // Four bands, in the order somebody would work them. A CVE belongs to
  // exactly one: KEV membership outranks any score, and an unscored CVE is
  // not silently treated as a low one.
  const exploited = entries.filter((e) => e.in_kev);
  const likely = entries.filter(
    (e) => !e.in_kev && typeof e.epss_score === "number" && e.epss_score >= LIKELY,
  );
  const watch = entries.filter(
    (e) => !e.in_kev && typeof e.epss_score === "number" && e.epss_score < LIKELY,
  );
  const unscored = entries.filter((e) => !e.in_kev && typeof e.epss_score !== "number");

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Threat intelligence</h1>
        <span className="font-mono text-[11px] text-ink-3">
          {entries.length} CVE{entries.length === 1 ? "" : "s"} matched to open findings
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
        <>
          <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
            <Tile
              label="Exploited now"
              value={exploited.length}
              tone={exploited.length > 0 ? "critical" : "muted"}
              detail="In CISA KEV"
            />
            <Tile
              label="Likely"
              value={likely.length}
              tone={likely.length > 0 ? "warn" : "muted"}
              detail={`EPSS ≥ ${LIKELY * 100}%`}
            />
            <Tile label="Watch" value={watch.length} tone="muted" detail="Scored, below the line" />
            <Tile
              label="Unscored"
              value={unscored.length}
              tone="muted"
              detail="Not a low score — no score"
            />
          </div>

          <Band
            title="Exploited in the wild"
            detail="CISA has observed these being used in attacks. A fact, not a forecast — it outranks every score below."
            tone="critical"
            entries={exploited}
          />
          <Band
            title="Likely to be exploited"
            detail={`EPSS puts these at ${LIKELY * 100}% or more within thirty days. A probability that moves day to day, so the fetch time matters.`}
            tone="warn"
            entries={likely}
          />
          <Band
            title="Scored, below the line"
            detail="Published, matched to an open finding, and currently not thought likely. Worth knowing about; not worth interrupting anybody for."
            tone="muted"
            entries={watch}
          />
          <Band
            title="Not yet scored"
            detail="The refresh has not reached these. An absent score is not a low one, which is why they are here rather than at the bottom of a list sorted by score."
            tone="muted"
            entries={unscored}
          />
        </>
      )}

      <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
        <Label>Reading this list</Label>
        <br />
        Only findings with a CVE appear: most SAST and IaC findings describe a
        code pattern rather than a published vulnerability, and there is no
        equivalent public feed for those — inventing one would be a confidence
        this page does not have. A CVE sits in exactly one band, and KEV
        membership outranks any score.
      </p>
    </div>
  );
}

function Tile({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: number;
  detail: string;
  tone: "critical" | "warn" | "muted";
}) {
  const colour =
    tone === "critical" ? "text-critical" : tone === "warn" ? "text-high" : "text-ink-2";
  return (
    <div className="border border-rule bg-paper-2 px-3 py-2">
      <div className="font-mono text-[9px] uppercase tracking-[0.12em] text-ink-3">{label}</div>
      <div className={`font-mono text-xl font-bold tabular ${colour}`}>{value}</div>
      <div className="text-[9px] leading-snug text-ink-3">{detail}</div>
    </div>
  );
}

function Band({
  title,
  detail,
  tone,
  entries,
}: {
  title: string;
  detail: string;
  tone: "critical" | "warn" | "muted";
  entries: ThreatIntelEntry[];
}) {
  // An empty band is not drawn. Four permanently-visible headings, three of
  // them empty, is the shape that made the old page feel like a form.
  if (entries.length === 0) return null;

  const edge =
    tone === "critical" ? "border-l-critical" : tone === "warn" ? "border-l-high" : "border-l-rule";

  return (
    <section className={`flex flex-col gap-2 border-l-2 pl-3 ${edge}`}>
      <div className="flex flex-wrap items-baseline gap-2">
        <h2 className="text-[13px] font-bold">{title}</h2>
        <span className="font-mono text-[10px] text-ink-3">{entries.length}</span>
      </div>
      <p className="max-w-prose text-[10px] leading-relaxed text-ink-3">{detail}</p>

      <div className="flex flex-col">
        {entries.map((entry) => (
          <div
            key={entry.cve_id}
            className="grid grid-cols-[minmax(9rem,auto)_1fr] items-baseline gap-x-3 gap-y-1 border-b border-rule-soft py-1.5 last:border-0 sm:grid-cols-[minmax(9rem,auto)_7rem_1fr]"
          >
            <div className="flex flex-wrap items-baseline gap-1.5">
              <Link
                href={`/triage?rule_id=${encodeURIComponent(entry.cve_id)}`}
                className="font-mono text-[11px] font-semibold text-ink hover:text-accent"
              >
                {entry.cve_id}
              </Link>
              <SeverityText severity={entry.worst_severity as Severity} />
              {entry.in_kev && entry.kev_added_at ? (
                <span className="font-mono text-[9px] text-ink-3">
                  listed <RelativeTime value={entry.kev_added_at} />
                </span>
              ) : null}
            </div>

            <EpssBar score={entry.epss_score} />

            <div className="font-mono text-[9px] text-ink-3">
              {entry.finding_count} finding{entry.finding_count === 1 ? "" : "s"} ·{" "}
              {entry.repo_full_names.map((repo, index) => (
                <span key={repo}>
                  {index > 0 ? ", " : ""}
                  <span className="text-ink-2">{repo}</span>
                </span>
              ))}
              {entry.fetched_at ? (
                <>
                  {" · "}
                  <RelativeTime value={entry.fetched_at} />
                </>
              ) : (
                <span title="The daily refresh job hasn't reached this CVE yet">
                  {" · never fetched"}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

/**
 * EPSS as a magnitude rather than a number in a column.
 *
 * A probability has a size, and "3.1%" beside "61.4%" in a monospace column
 * makes the reader compare digits. The bar does that comparison for them; the
 * number stays, because the exact value is what somebody quotes in a ticket.
 */
function EpssBar({ score }: { score: number | null | undefined }) {
  if (typeof score !== "number") {
    return (
      <span className="font-mono text-[9px] text-ink-3" title="Not yet fetched, or not scored">
        no score
      </span>
    );
  }
  const percent = score * 100;
  return (
    <span className="flex items-center gap-1.5" title={`EPSS ${percent.toFixed(1)}%`}>
      <span className="h-1.5 w-10 shrink-0 bg-paper-3" aria-hidden="true">
        <span
          className={`block h-full ${score >= LIKELY ? "bg-high" : "bg-accent-2"}`}
          // Sub-1% scores are the common case and a bar rounded to zero pixels
          // reads as "no data", which is a different answer.
          style={{ width: `${Math.max(percent, 2)}%` }}
        />
      </span>
      <span
        className={`font-mono text-[10px] tabular ${score >= LIKELY ? "font-bold text-high" : "text-ink-2"}`}
      >
        {percent.toFixed(1)}%
      </span>
    </span>
  );
}
