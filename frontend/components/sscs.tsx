/**
 * Supply-chain evidence for one repository (spec 07, spec 10 §9).
 *
 * Three things a reader wants: how trustworthy the dependency tree is now, how
 * that has moved, and where the SBOM for a given release is. The trust score's
 * arithmetic travels with each row, so the number is checkable rather than
 * asserted — the same rule Oracle's decisions follow.
 */

import {
  EmptyState,
  Label,
  Pill,
  RelativeTime,
  StatTile,
} from "@/components/primitives";
import type { SscsEvidence } from "@/lib/api";

type ScoreTerm = { key: string; penalty: number; detail: string; count: number };

type Ecosystems = {
  ecosystems?: {
    ecosystem: string;
    dependency_count: number;
    critical_vulns: number;
    high_vulns: number;
    medium_vulns: number;
    low_vulns: number;
    floating_versions: number;
    stale_dependencies: number;
  }[];
  score_terms?: ScoreTerm[];
  floored?: boolean;
};

const TERM_LABEL: Record<string, string> = {
  critical_vulnerabilities: "Critical advisories",
  high_vulnerabilities: "High advisories",
  medium_vulnerabilities: "Medium advisories",
  floating_versions: "Unpinned versions",
  stale_dependencies: "Unmaintained packages",
};

/** Higher is better here, unlike every other score in the platform. */
function trustTone(
  score: number | null | undefined,
): "critical" | "warn" | "pass" | "muted" {
  // Null is not zero and not a hundred. The scan resolved nothing, so there is
  // no trust to be good or bad about (spec 07 §5a).
  if (score == null) return "muted";
  if (score < 50) return "critical";
  if (score < 80) return "warn";
  return "pass";
}

export function SscsTab({
  repoId,
  evidence,
  latest,
}: {
  repoId: string;
  evidence: SscsEvidence[];
  latest: SscsEvidence | null;
}) {
  if (!latest) {
    return (
      <EmptyState
        title="No supply-chain evidence"
        detail={
          <>
            Enable the <span className="font-mono">atlas</span> capability to
            scan dependencies on manifest changes, and to generate an SBOM and
            provenance statement on every release.
          </>
        }
      />
    );
  }

  const detail = (latest.ecosystems_json ?? {}) as Ecosystems;
  const terms = detail.score_terms ?? [];
  const releases = evidence.filter((row) => row.sbom_ref);
  // A scan ran; it just resolved nothing to score. That is a different state
  // from "no scan has run", which is the empty state above, and from a low
  // score, which is a finding about the dependencies.
  const assessed = latest.trust_score != null;

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <StatTile
          label="Trust score"
          value={assessed ? `${latest.trust_score}/100` : "—"}
          sub={
            !assessed
              ? "not assessed"
              : detail.floored
                ? "at the floor — see raw score"
                : "higher is better"
          }
          alert={assessed && (latest.trust_score ?? 0) < 50}
        />
        <StatTile
          label="Dependencies"
          value={latest.dependency_count}
          sub="direct and transitive"
        />
        <StatTile
          label="With advisories"
          value={latest.vulnerable_dependency_count}
          sub="counted per package"
          alert={latest.vulnerable_dependency_count > 0}
        />
        <StatTile
          label="Ecosystems"
          value={detail.ecosystems?.length ?? 0}
          sub={(detail.ecosystems ?? []).map((e) => e.ecosystem).join(", ")}
        />
      </div>

      {!assessed ? (
        <section className="border border-high bg-high-wash p-2.5">
          <Label>Not assessed</Label>
          <p className="mt-1 max-w-prose text-[11px] leading-relaxed text-ink-2">
            {terms[0]?.detail ??
              "The scan resolved no dependencies, so no supply-chain trust was assessed."}{" "}
            This is not a clean result. Until the manifests resolve to a pinned
            set, the trust score is unknown rather than perfect, and it counts
            as neither evidence for a maturity tier nor a term in a risk
            decision.
          </p>
        </section>
      ) : terms.length > 0 ? (
        <section>
          <Label>How the trust score was reached</Label>
          <table className="mt-1.5 w-auto border-collapse font-mono text-[10px]">
            <tbody>
              <tr>
                <td className="tabular w-14 py-0.5 pr-3 text-right text-ink">100</td>
                <td className="py-0.5 pr-6 text-ink-2">starting point</td>
                <td className="py-0.5 text-ink-3" />
              </tr>
              {terms.map((term) => (
                <tr key={term.key}>
                  <td className="tabular w-14 py-0.5 pr-3 text-right text-ink">
                    −{term.penalty.toFixed(1)}
                  </td>
                  <td className="py-0.5 pr-6 text-ink-2">
                    {TERM_LABEL[term.key] ?? term.key}
                  </td>
                  <td className="py-0.5 text-ink-3">{term.detail}</td>
                </tr>
              ))}
              <tr className="border-t border-rule-soft">
                <td className="tabular w-14 py-0.5 pr-3 text-right font-bold">
                  {latest.trust_score}
                </td>
                <td className="py-0.5 pr-6 font-bold text-ink-2">trust score</td>
                <td className="py-0.5 text-ink-3">
                  {detail.floored
                    ? `clamped up from ${latest.raw_trust_score?.toFixed(1)}`
                    : "within range"}
                </td>
              </tr>
            </tbody>
          </table>
          <p className="mt-1.5 max-w-prose text-[11px] leading-relaxed text-ink-3">
            Advisory counts are curved rather than summed, so more
            vulnerabilities always score worse without five criticals and five
            hundred both reaching zero. Ratio terms stay linear because a ratio
            cannot saturate.
          </p>
        </section>
      ) : null}

      {releases.length > 0 ? (
        <section>
          <Label>Release evidence</Label>
          <div className="scroll-x mt-1.5 border border-rule">
            <table className="w-full min-w-[560px] border-collapse bg-paper-2 font-mono text-[11px]">
              <thead>
                <tr className="border-b-2 border-ink-2 text-left">
                  {["Release", "Commit", "Trust", "SBOM", "Builder", "When"].map(
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
                {releases.map((row) => {
                  const provenance = (row.provenance_json ?? {}) as Record<
                    string,
                    string
                  >;
                  return (
                    <tr
                      key={row.evidence_id}
                      className="border-b border-rule-soft last:border-b-0"
                    >
                      <td className="px-2 py-2 font-semibold">
                        {row.tag_or_release}
                      </td>
                      <td className="px-2 py-2 text-ink-3">
                        {row.commit_sha?.slice(0, 7)}
                      </td>
                      <td className="px-2 py-2">
                        <Pill tone={trustTone(row.trust_score)}>
                          {row.trust_score ?? "n/a"}
                        </Pill>
                      </td>
                      <td className="max-w-[28ch] truncate px-2 py-2 text-ink-2">
                        {/* The archived file itself, not just its path
                            (spec 18 §8.2) — admin-only, the same gate every
                            other raw tool output already sits behind. */}
                        <a
                          href={`/api/repos/${repoId}/sscs/sbom?evidence_id=${row.evidence_id}`}
                          className="text-accent underline-offset-2 hover:underline"
                          title={row.sbom_ref ?? undefined}
                        >
                          download
                        </a>
                      </td>
                      <td className="px-2 py-2 text-ink-3">
                        {provenance.builder_id ?? "—"}
                      </td>
                      <td className="whitespace-nowrap px-2 py-2 text-ink-3">
                        <RelativeTime value={row.evaluated_at} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      <section>
        <Label>Trust over time</Label>
        {/* Oldest first, so the line reads left to right the way a trend does.
            The API returns newest first because that is what every other view
            wants. */}
        <TrustSparkline rows={[...evidence].reverse()} />
      </section>
    </div>
  );
}

function TrustSparkline({ rows }: { rows: SscsEvidence[] }) {
  // Unassessed scans are dropped rather than plotted at zero or carried
  // forward (spec 07 §5a): a scan that resolved nothing is not a data point
  // about trust, and either substitute would draw a line the evidence does
  // not support.
  const scored = rows.filter(
    (row): row is SscsEvidence & { trust_score: number } => row.trust_score != null,
  );
  const skipped = rows.length - scored.length;

  if (scored.length < 2) {
    return (
      <p className="mt-1 text-[11px] text-ink-3">
        {scored.length === 0
          ? `No scan has resolved dependencies yet${skipped > 0 ? ` (${skipped} assessed nothing)` : ""}.`
          : "One data point so far. A trend needs at least two scans."}
      </p>
    );
  }

  const width = 420;
  const height = 56;
  const step = width / (scored.length - 1);
  const points = scored
    .map((row, index) => {
      const x = index * step;
      const y = height - (Math.max(0, Math.min(100, row.trust_score)) / 100) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  const last = scored[scored.length - 1];
  const lastX = width;
  const lastY = height - (last.trust_score / 100) * height;

  return (
    <div className="scroll-x mt-1.5">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-14 w-full min-w-[320px] max-w-[420px] border border-rule bg-paper-2"
        role="img"
        aria-label={`Trust score across ${scored.length} scans, currently ${last.trust_score} of 100`}
      >
        {/* The 50 line is the default release floor, so the shape is readable
            against the threshold that matters rather than in the abstract. */}
        <line
          x1="0"
          y1={height / 2}
          x2={width}
          y2={height / 2}
          stroke="currentColor"
          strokeWidth="0.5"
          className="text-rule"
          strokeDasharray="3 3"
        />
        <polyline
          points={points}
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          className={
            last.trust_score < 50
              ? "text-critical"
              : last.trust_score < 80
                ? "text-high"
                : "text-pass"
          }
        />
        <circle cx={lastX} cy={lastY} r="2.5" className="fill-current" />
      </svg>
      <p className="mt-1 font-mono text-[9px] text-ink-3">
        {scored.length} scans · dashed line is the default release floor of 50
        {skipped > 0 ? ` · ${skipped} not assessed, omitted` : ""}
      </p>
    </div>
  );
}
