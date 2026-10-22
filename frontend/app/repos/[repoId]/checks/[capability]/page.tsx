import Link from "next/link";

import { LaneControl } from "@/components/lane-control";
import { getScanRuns } from "@/lib/server";
import {
  CAPABILITY_META,
  Crumb,
  EmptyState,
  ErrorPanel,
  Pill,
  RelativeTime,
  Section,
} from "@/components/primitives";
import {
  HISTORY_PAGE_SIZE,
  checkHref,
  exactTime,
  laneLabel,
  laneTone,
  lanesToOffer,
  parseHistoryFilter,
  percent,
  runDuration,
  scanRunHref,
  shortSha,
} from "@/lib/checks";
import type { ScanRunRow } from "@/lib/api";
import type { CheckLane } from "@/lib/checks";

export const dynamic = "force-dynamic";

export const metadata = { title: "Check history — Mykronos" };

function statusTone(status: string) {
  if (status === "success") return "pass" as const;
  if (status === "no_applicable_targets") return "muted" as const;
  return "critical" as const;
}

/**
 * One check's run history (TheHub #60819): every run of a capability on a
 * repository, newest first, each linking to its full report.
 *
 * Reached by clicking a check — a tile on the repo Dashboard or Harness tab,
 * or a cell in the portfolio's capability column. Where several tools or jobs
 * report under the capability, the page offers to narrow to one.
 */
export default async function CheckHistoryPage({
  params,
  searchParams,
}: {
  params: Promise<{ repoId: string; capability: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { repoId, capability: rawCapability } = await params;
  const capability = decodeURIComponent(rawCapability);
  const filter = parseHistoryFilter(await searchParams);
  const result = await getScanRuns(repoId, capability, {
    ...filter,
    limit: HISTORY_PAGE_SIZE,
  });
  if (!result.ok) {
    return <ErrorPanel title="Check history unavailable" detail={result.error} />;
  }
  const page = result.data;
  const meta = CAPABILITY_META[capability as keyof typeof CAPABILITY_META];
  const lanes = lanesToOffer(page.lanes);
  const narrowed = Boolean(filter.tool || filter.job);
  const total = page.lanes.reduce((sum, lane) => sum + lane.runs, 0);

  return (
    <div className="flex flex-col gap-4">
      <div className="font-mono text-[12px] text-ink-3">
        <Crumb href="/">Portfolio</Crumb> /{" "}
        <Crumb href={`/repos/${repoId}`}>{page.repo_full_name}</Crumb> /{" "}
        <span className="text-ink-2">{capability} history</span>
      </div>

      <header className="flex flex-col gap-1">
        <h1 className="flex items-baseline gap-2 text-xl font-semibold leading-snug">
          <span aria-hidden>{meta?.icon ?? "•"}</span>
          {meta?.label ?? capability}
        </h1>
        <p className="font-mono text-[12px] text-ink-3">
          {total} run{total === 1 ? "" : "s"} recorded · newest first · click a run for its
          full report
        </p>
      </header>

      {lanes.length ? (
        <nav
          aria-label="Narrow to one tool or job"
          className="flex flex-wrap items-baseline gap-1.5 font-mono text-[12px]"
        >
          <span className="text-ink-3">reported by</span>
          <Link
            href={checkHref(repoId, capability)}
            className={`border px-2 py-0.5 ${
              narrowed ? "border-rule text-ink-3 hover:border-accent" : "border-accent text-accent"
            }`}
          >
            all ({total})
          </Link>
          {lanes.map((lane) => {
            // A job names a lane more specifically than a tool; narrow by it
            // when there is one, so two jobs of one tool stay apart.
            const target = lane.job
              ? { job: lane.job }
              : { tool: lane.tool_name };
            const active = lane.job
              ? filter.job === lane.job
              : !filter.job && filter.tool === lane.tool_name;
            return (
              <Link
                key={`${lane.tool_name ?? ""}/${lane.job ?? ""}`}
                href={checkHref(repoId, capability, target)}
                className={`border px-2 py-0.5 ${
                  active ? "border-accent text-accent" : "border-rule text-ink-3 hover:border-accent"
                }`}
              >
                {laneLabel(lane)} ({lane.runs})
              </Link>
            );
          })}
        </nav>
      ) : null}

      {page.lanes.length ? (
        <Section
          title="Lanes"
          detail="a lane that stopped reads stale or retired, never current"
        >
          <ul className="flex flex-col divide-y divide-rule-soft font-mono text-[12px]">
            {page.lanes.map((lane) => (
              <LaneRow
                key={`${lane.tool_name ?? ""}/${lane.job ?? ""}`}
                repoId={repoId}
                capability={capability}
                lane={lane}
              />
            ))}
          </ul>
        </Section>
      ) : null}

      {page.runs.length === 0 ? (
        <EmptyState
          title={
            page.offset > 0
              ? "No more runs"
              : narrowed
                ? "No runs from this tool or job"
                : "No runs recorded for this check"
          }
          detail={
            page.offset > 0 ? (
              <>
                This page is past the last run.{" "}
                <Link
                  className="underline"
                  href={checkHref(repoId, capability, { tool: filter.tool, job: filter.job })}
                >
                  Back to the newest
                </Link>
                .
              </>
            ) : (
              <>
                {page.repo_full_name} has never reported a {capability} run
                {narrowed ? " from this tool or job" : ""}. A check that is
                enabled and has never run is a gap: the repository looks covered
                and nothing disagrees, because there is nothing to disagree with.
                Aegis, Oracle and Patchwork record no scan runs by design.
              </>
            )
          }
        />
      ) : (
        <Section
          title="Runs"
          detail={`${page.offset + 1}–${page.offset + page.runs.length}${
            page.has_more ? " · more below" : ""
          }`}
        >
          <div className="scroll-x">
            <table className="w-full min-w-[860px] border-collapse font-mono text-[12px]">
              <thead>
                <tr className="border-b border-rule text-left">
                  {["Status", "Started", "Finished", "Commit", "Branch", "Tool / job", "Findings", ""].map(
                    (heading) => (
                      <th
                        key={heading}
                        className={`whitespace-nowrap px-2 py-1.5 text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3 ${
                          heading === "Findings" ? "text-right" : ""
                        }`}
                      >
                        {heading}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {page.runs.map((run) => (
                  <RunRow key={run.scan_run_id} repoId={repoId} run={run} />
                ))}
              </tbody>
            </table>
          </div>
          {page.offset > 0 || page.has_more ? (
            <div className="flex justify-between border-t border-rule-soft px-3 py-2 font-mono text-[12px]">
              {page.offset > 0 ? (
                <Link
                  className="underline"
                  href={checkHref(repoId, capability, {
                    ...filter,
                    offset: Math.max(0, page.offset - HISTORY_PAGE_SIZE),
                  })}
                >
                  ← newer
                </Link>
              ) : (
                <span />
              )}
              {page.has_more ? (
                <Link
                  className="underline"
                  href={checkHref(repoId, capability, {
                    ...filter,
                    offset: page.offset + HISTORY_PAGE_SIZE,
                  })}
                >
                  older →
                </Link>
              ) : null}
            </div>
          ) : null}
        </Section>
      )}
    </div>
  );
}

/** One lane with its state (TheHub #60816) and the operator's control. */
function LaneRow({
  repoId,
  capability,
  lane,
}: {
  repoId: string;
  capability: string;
  lane: CheckLane;
}) {
  return (
    <li className="flex flex-wrap items-baseline gap-2 px-3 py-2">
      {lane.state ? <Pill tone={laneTone(lane.state)}>{lane.state}</Pill> : null}
      <span className="text-ink">{laneLabel(lane)}</span>
      <span className="text-ink-3">
        {lane.runs} run{lane.runs === 1 ? "" : "s"}
        {lane.last_run_at ? (
          <>
            {" "}
            · last <RelativeTime value={lane.last_run_at} />
          </>
        ) : null}
      </span>
      {lane.state_reason ? (
        <span className="basis-full text-[11px] text-ink-2">{lane.state_reason}</span>
      ) : null}
      {lane.reported_since_retired ? (
        <span className="basis-full text-[11px] text-warn">
          It has reported since it was retired: restore it if it is in use.
        </span>
      ) : null}
      <span className="ml-auto">
        <LaneControl repoId={repoId} capability={capability} lane={lane} />
      </span>
    </li>
  );
}

function RunRow({ repoId, run }: { repoId: string; run: ScanRunRow }) {
  const href = scanRunHref(repoId, run.scan_run_id);
  const sha = shortSha(run.commit_sha);
  const duration = runDuration(run.started_at, run.completed_at);
  const coverage = percent(run.line_coverage);

  return (
    <tr className="border-b border-rule-soft align-baseline last:border-b-0 hover:bg-paper-3">
      <td className="whitespace-nowrap px-2 py-1.5">
        <Link href={href} className="tap" aria-label={`Open run ${run.scan_run_id}`}>
          <Pill tone={statusTone(run.scan_status)}>{run.scan_status.replace(/_/g, " ")}</Pill>
        </Link>
      </td>
      <td className="whitespace-nowrap px-2 py-1.5" title={exactTime(run.started_at) ?? undefined}>
        {run.started_at ? <RelativeTime value={run.started_at} /> : "—"}
      </td>
      <td className="whitespace-nowrap px-2 py-1.5 text-ink-2">
        {run.completed_at ? (
          <span title={exactTime(run.completed_at) ?? undefined}>
            <RelativeTime value={run.completed_at} />
            {duration ? <span className="text-ink-3"> · {duration}</span> : null}
          </span>
        ) : (
          <span className="text-ink-3">not finished</span>
        )}
      </td>
      <td className="whitespace-nowrap px-2 py-1.5">
        {sha ? (
          run.commit_url ? (
            <a
              href={run.commit_url}
              target="_blank"
              rel="noreferrer"
              className="underline decoration-dotted hover:text-accent"
              title={run.commit_sha ?? undefined}
            >
              {sha}
            </a>
          ) : (
            <span title={run.commit_sha ?? undefined}>{sha}</span>
          )
        ) : (
          <span className="text-ink-3">—</span>
        )}
        {run.pr_number ? <span className="text-ink-3"> · PR #{run.pr_number}</span> : null}
      </td>
      <td className="whitespace-nowrap px-2 py-1.5 text-ink-2">{run.branch ?? "—"}</td>
      <td className="px-2 py-1.5 text-ink-2">
        {run.tool_name ?? "unknown"}
        {run.tool_version ? <span className="text-ink-3"> {run.tool_version}</span> : null}
        {run.job ? <span className="block text-[11px] text-ink-3">job {run.job}</span> : null}
      </td>
      <td className="tabular whitespace-nowrap px-2 py-1.5 text-right">
        {run.finding_count ?? "—"}
        {coverage ? (
          <span className="block text-[11px] text-ink-3" title="Line coverage — not a security metric">
            {coverage} lines
          </span>
        ) : null}
      </td>
      <td className="whitespace-nowrap px-2 py-1.5 text-right">
        <Link href={href} className="underline hover:text-accent">
          full report →
        </Link>
        {run.detail ? (
          <span className="block max-w-[28ch] truncate text-left text-[11px] text-ink-3" title={run.detail}>
            {run.detail}
          </span>
        ) : null}
      </td>
    </tr>
  );
}
