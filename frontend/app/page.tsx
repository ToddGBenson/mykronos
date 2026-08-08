import Link from "next/link";

import { getPortfolio } from "@/lib/server";
import {
  CapabilityDots,
  Crumb,
  EmptyState,
  ErrorPanel,
  Label,
  Pill,
  RelativeTime,
  ScoreMeter,
  SeverityBar,
  StatTile,
  Verdict,
} from "@/components/primitives";

export const dynamic = "force-dynamic";

export default async function PortfolioPage({
  searchParams,
}: {
  searchParams: Promise<{ removed?: string }>;
}) {
  const params = await searchParams;
  const includeRemoved = params.removed === "1";
  const result = await getPortfolio(includeRemoved);

  if (!result.ok) {
    return <ErrorPanel title="Portfolio unavailable" detail={result.error} />;
  }

  const { summary, repos } = result.data;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Portfolio</h1>
        <span className="font-mono text-[11px] text-ink-3">
          {summary.active_repos} active
          {repos.length !== summary.active_repos
            ? ` · ${repos.length - summary.active_repos} other`
            : ""}
        </span>
        <Link
          href={includeRemoved ? "/" : "/?removed=1"}
          className="ml-auto border border-rule px-2 py-1 font-mono text-[10px] text-ink-3 hover:border-accent hover:text-accent"
        >
          {includeRemoved ? "hide removed" : "include removed"}
        </Link>
      </div>

      <div className="grid grid-cols-2 gap-2 lg:grid-cols-5">
        <StatTile
          label="Open critical"
          value={summary.open_critical}
          alert={summary.open_critical > 0}
        />
        <StatTile label="Open high" value={summary.open_high} />
        <StatTile
          label="Oracle: no go"
          value={summary.repos_no_go}
          sub={
            summary.repos_not_assessed
              ? `${summary.repos_not_assessed} not assessed`
              : "all repos assessed"
          }
          alert={summary.repos_no_go > 0}
        />
        <StatTile
          label="Awaiting first scan"
          value={summary.repos_awaiting_first_scan}
          sub="onboarded, never scanned"
        />
        <StatTile
          label="Stale > 7d"
          value={summary.repos_with_stale_scans}
          sub="repos"
        />
      </div>

      {repos.length === 0 ? (
        <EmptyState
          title="No repositories onboarded yet"
          detail={
            <>
              Install the GitHub App on a repository, then enable capabilities.
              Until the App is registered the platform runs against an in-memory
              GitHub and no real repository is touched.
            </>
          }
        />
      ) : (
        <div className="scroll-x border border-rule">
          <table className="w-full min-w-[860px] border-collapse bg-paper-2 font-mono text-[11px]">
            <thead>
              <tr className="border-b-2 border-ink-2 text-left">
                {[
                  "Repository",
                  "Capabilities",
                  "Risk",
                  "Oracle",
                  "Severity mix",
                  "C",
                  "H",
                  "M",
                  "Last scan",
                ].map((heading, index) => (
                  <th
                    key={heading}
                    className={`whitespace-nowrap px-2 py-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-ink-3 ${
                      index >= 5 && index <= 7 ? "text-right" : ""
                    }`}
                  >
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {repos.map((repo) => (
                <tr
                  key={repo.repo_id}
                  className="border-b border-rule-soft last:border-b-0 hover:bg-paper-3"
                >
                  <td className="px-2 py-2">
                    <Link
                      href={`/repos/${repo.repo_id}`}
                      className="font-semibold text-ink hover:text-accent"
                    >
                      {repo.repo_full_name}
                    </Link>
                    {repo.status !== "active" ? (
                      <span className="ml-2">
                        <Pill tone={repo.status === "removed" ? "muted" : "warn"}>
                          {repo.status.replace("_", " ")}
                        </Pill>
                      </span>
                    ) : null}
                  </td>

                  <td className="px-2 py-2">
                    <CapabilityDots
                      enabled={repo.enabled_capabilities}
                      pending={repo.pending_capabilities ?? []}
                    />
                  </td>

                  {/* Null, not zero — "not assessed" is its own state, and
                      Oracle is opt-in, so plenty of repos stay here. */}
                  <td className="px-2 py-2">
                    {typeof repo.risk_score === "number" ? (
                      <ScoreMeter score={repo.risk_score} />
                    ) : (
                      <span className="text-ink-3">—</span>
                    )}
                  </td>
                  <td className="px-2 py-2">
                    <Verdict
                      recommendation={repo.recommendation}
                      score={repo.risk_score}
                    />
                  </td>

                  <td className="px-2 py-2">
                    {repo.awaiting_first_scan ? (
                      <Pill tone="muted">awaiting 1st scan</Pill>
                    ) : (
                      <SeverityBar counts={repo.severity_counts} />
                    )}
                  </td>

                  {(["critical", "high", "medium"] as const).map((severity) => (
                    <td key={severity} className="tabular px-2 py-2 text-right">
                      {repo.awaiting_first_scan
                        ? "—"
                        : (repo.severity_counts[severity] ?? 0)}
                    </td>
                  ))}

                  <td
                    className={`whitespace-nowrap px-2 py-2 ${
                      repo.is_stale ? "text-high" : "text-ink-2"
                    }`}
                  >
                    <RelativeTime value={repo.last_scan_at} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
        <Label>Reading this table</Label>
        <br />
        Ten capability slots per repo, so coverage gaps read down the column. A
        hollow dot outlined in the accent is enabled but pending its install PR
        — not yet running. Risk is Oracle&rsquo;s standing score, refreshed
        daily, with ticks on the track at the review and no-go thresholds. A
        repo showing <span className="font-mono">not assessed</span> has not
        enabled <span className="font-mono">oracle</span> — that is a choice, not
        a gap, and it reads as <span className="font-mono">—</span> rather than{" "}
        <span className="font-mono">0</span>, which would mean &ldquo;assessed,
        no risk&rdquo;. For what to work on next rather than which repo is
        worst, use the <Crumb href="/triage">triage queue</Crumb>.
      </p>
    </div>
  );
}
