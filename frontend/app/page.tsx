import Link from "next/link";

import { getBoardCounts, getPortfolio } from "@/lib/server";
import {
  buildBoard,
  severityLine,
  TILE_ORDER,
  TILE_WORD,
  type BoardCounts,
  type BoardSort,
} from "@/lib/portfolio-board";
import { EmptyState, ErrorPanel, Pill, StatTile, Verdict } from "@/components/primitives";
import { BoardLegend, BoardTile } from "@/components/portfolio-board";
import { ProdLag } from "@/components/prod-lag";

export const dynamic = "force-dynamic";

type Params = { removed?: string; sort?: string; benchmark?: string };

/** The link for these view settings, with `patch` applied. */
function viewHref(params: Params, patch: Partial<Params>): string {
  const merged = { ...params, ...patch };
  const query = new URLSearchParams();
  if (merged.sort === "az") query.set("sort", "az");
  if (merged.benchmark === "1") query.set("benchmark", "1");
  if (merged.removed === "1") query.set("removed", "1");
  const qs = query.toString();
  return qs ? `/?${qs}` : "/";
}

const TOGGLE =
  "inline-flex min-h-11 items-center border px-3 font-mono text-[12px] sm:min-h-9";

/**
 * Portfolio: a status board (TheHub #61138, design v2 P4 and P6).
 *
 * Each product is a band of twelve tiles, one per capability or lane, and a
 * band with problems sorts first. It replaces the table of 15px capability
 * cells, which had to be hovered one by one to be read. The repository page
 * still has all fifteen capabilities and the full row of numbers.
 */
export default async function PortfolioPage({
  searchParams,
}: {
  searchParams: Promise<Params>;
}) {
  const params = await searchParams;
  const includeRemoved = params.removed === "1";
  const showBenchmark = params.benchmark === "1";
  const sort: BoardSort = params.sort === "az" ? "az" : "problems";
  const result = await getPortfolio(includeRemoved);

  if (!result.ok) {
    return <ErrorPanel title="Portfolio unavailable" detail={result.error} />;
  }

  const { summary, repos: all } = result.data;
  const benchmarks = all.filter((repo) => repo.synthetic).length;
  const shown = showBenchmark ? all : all.filter((repo) => !repo.synthetic);

  // Two reads per repository, side by side. A failure leaves that band's
  // tiles on their run state alone, and the page says so.
  const fetched = await Promise.all(shown.map((repo) => getBoardCounts(repo.repo_id)));
  const counts: Record<string, BoardCounts | null> = {};
  let countsMissing = 0;
  shown.forEach((repo, i) => {
    const got = fetched[i];
    counts[repo.repo_id] = got?.ok ? got.data : null;
    if (!got?.ok) countsMissing += 1;
  });

  const { now, bands, summary: board } = buildBoard(shown, sort, counts);
  const summaryLine = TILE_ORDER.filter((state) => state !== "healthy" && board[state] > 0)
    .map((state) => `${board[state]} ${TILE_WORD[state]}`)
    .join(" · ");

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h1 className="font-bold tracking-tight">Portfolio</h1>
          <span className="font-mono text-[13px] text-ink-2">
            {summaryLine || `${bands.length} products, every tile healthy`}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex" role="group" aria-label="Sort">
            <Link
              href={viewHref(params, { sort: undefined })}
              aria-current={sort === "problems" ? "true" : undefined}
              className={`${TOGGLE} ${sort === "problems" ? "border-accent bg-accent-wash text-ink" : "border-rule text-ink-3 hover:text-accent"}`}
            >
              Problems first
            </Link>
            <Link
              href={viewHref(params, { sort: "az" })}
              aria-current={sort === "az" ? "true" : undefined}
              className={`${TOGGLE} -ml-px ${sort === "az" ? "border-accent bg-accent-wash text-ink" : "border-rule text-ink-3 hover:text-accent"}`}
            >
              A–Z
            </Link>
          </span>
          {benchmarks ? (
            <Link
              href={viewHref(params, { benchmark: showBenchmark ? undefined : "1" })}
              className={`${TOGGLE} border-rule text-ink-3 hover:border-accent hover:text-accent`}
            >
              {showBenchmark ? "Hide benchmark" : `Show benchmark (${benchmarks})`}
            </Link>
          ) : null}
          <Link
            href={viewHref(params, { removed: includeRemoved ? undefined : "1" })}
            className={`${TOGGLE} border-rule text-ink-3 hover:border-accent hover:text-accent`}
          >
            {includeRemoved ? "Hide removed" : "Include removed"}
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <StatTile
          label="Open critical"
          value={summary.open_critical}
          alert={summary.open_critical > 0}
        />
        <StatTile label="Open high" value={summary.open_high} />
        <StatTile
          label="Risk decision: no go"
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
        <StatTile label="Stale > 7d" value={summary.repos_with_stale_scans} sub="repos" />
        <StatTile
          label="Overdue"
          value={summary.overdue_findings}
          sub="past their target"
          alert={summary.overdue_findings > 0}
        />
      </div>

      {countsMissing ? (
        <p role="status" className="border border-high bg-high-wash px-3 py-2 text-[13px] text-ink">
          {`For ${countsMissing} of ${bands.length} products the overdue and accepted counts could not be read, so those tiles show their last run only.`}
        </p>
      ) : null}

      {bands.length === 0 ? (
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
        <ol className="flex flex-col gap-3">
          {bands.map(({ repo, tiles, needs }) => {
            const headingId = `band-${repo.repo_id}`;
            return (
              <li key={repo.repo_id}>
                <section
                  aria-labelledby={headingId}
                  className={`flex flex-col gap-2 border bg-paper-2 p-3 ${needs ? "border-ink-3" : "border-rule"}`}
                >
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                    <h2 id={headingId} className="text-[15px] font-semibold">
                      <Link href={`/repos/${repo.repo_id}`} className="tap text-ink hover:text-accent">
                        {repo.repo_full_name}
                      </Link>
                    </h2>
                    {repo.status !== "active" ? (
                      <Pill tone={repo.status === "removed" ? "muted" : "warn"}>
                        {repo.status.replace("_", " ")}
                      </Pill>
                    ) : null}
                    {repo.synthetic ? (
                      <Pill tone="muted">
                        <span title="A seeded benchmark corpus. Scanned like any other repository and counted in no portfolio total.">
                          benchmark
                        </span>
                      </Pill>
                    ) : null}
                    <ProdLag lag={repo.deploy_lag} />
                    <Verdict recommendation={repo.recommendation} score={repo.risk_score} />
                    <span className="tabular font-mono text-[12px] text-ink-2">
                      {repo.awaiting_first_scan
                        ? "awaiting first scan"
                        : severityLine(repo.severity_counts)}
                    </span>
                    <span
                      className={`font-mono text-[12px] ${needs ? "font-semibold text-ink" : "text-ink-3"}`}
                    >
                      {`${needs} need${needs === 1 ? "s" : ""} a look`}
                    </span>
                    <span className="ml-auto inline-flex gap-3">
                      <a
                        href={repo.github_url}
                        target="_blank"
                        rel="noreferrer"
                        className="tap font-mono text-[11px] text-ink-3 underline decoration-dotted hover:text-accent"
                      >
                        github
                      </a>
                      {repo.pipeline_url ? (
                        <a
                          href={repo.pipeline_url}
                          target="_blank"
                          rel="noreferrer"
                          className="tap font-mono text-[11px] text-ink-3 underline decoration-dotted hover:text-accent"
                        >
                          pipeline
                        </a>
                      ) : null}
                    </span>
                  </div>
                  <div className="grid grid-cols-4 gap-1 sm:grid-cols-6 xl:grid-cols-12">
                    {tiles.map((t) => (
                      <BoardTile
                        key={t.capability}
                        repoId={repo.repo_id}
                        capability={t.capability}
                        short={t.short}
                        label={t.label}
                        tile={t.tile}
                        now={now}
                      />
                    ))}
                  </div>
                </section>
              </li>
            );
          })}
        </ol>
      )}

      <div className="flex flex-col gap-2">
        <BoardLegend />
        <p className="max-w-prose text-[14px] leading-relaxed text-ink-3">
          A tile shows the age of its check&rsquo;s last run, its count of accepted findings,
          or its count of overdue findings and the oldest one&rsquo;s age, and opens that run
          history or those findings. Stale means no report for more than seven days, or none
          ever from an enabled check. The repository page has all fifteen capabilities and the
          severity mix; for what to work on next, use the{" "}
          <Link href="/triage" className="text-accent underline">
            triage queue
          </Link>
          .
        </p>
      </div>
    </div>
  );
}
