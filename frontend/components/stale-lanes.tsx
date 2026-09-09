import type { StaleLane } from "@/lib/api";

/**
 * Lanes that are reporting, and not covering (B-046).
 *
 * The section above this one lists lanes that cannot close findings because
 * they are failing or have gone quiet. These are the opposite shape and the
 * harder one to see: they succeed, on schedule, and every indicator in the
 * platform is green — against a tree that has stopped moving. A pipeline
 * pinned to a stale branch or a cached checkout produces a clean run forever
 * and never appears in any list of problems.
 *
 * TheHub's lanes surfaced only because they *also* went quiet for two days.
 * At their usual ten-hour cadence, 330 findings would have been frozen
 * against a stale tree with nothing anywhere saying so.
 *
 * **No button, deliberately.** Every other lane row on this page offers a
 * re-run, because for a stalled lane dispatching it is the fix. Here it is
 * not: the lane is already running and already succeeding, so a re-run
 * produces one more clean scan of the same stale tree and closes nothing. The
 * fix is in the pipeline definition, so the row links to the lane's CI view
 * and says what to change rather than offering an action that would look like
 * progress.
 */
export function StaleLanes({ lanes }: { lanes: StaleLane[] }) {
  if (!lanes.length) return null;

  return (
    <div className="flex flex-col gap-3">
      {lanes.map((lane) => (
        <div
          key={`${lane.repo_full_name}:${lane.capability}`}
          className="border-l-2 border-warn pl-3"
        >
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-mono text-[13px] text-ink">{lane.capability}</span>
            <span className="font-mono text-[12px] text-ink-2">{lane.repo_full_name}</span>
            <span className="font-mono text-[11px] uppercase tracking-wider text-warn">
              {lane.reason === "wrong_branch" ? "wrong branch" : "pinned commit"}
            </span>
          </div>

          <p className="mt-0.5 text-[12px] leading-snug text-ink-2">
            {lane.reason === "wrong_branch" ? (
              <>
                Scanning <code className="font-mono">{lane.branch}</code>, and the
                repository&rsquo;s default branch is{" "}
                <code className="font-mono">{lane.default_branch}</code>. Nothing on the
                default branch has been scanned by this lane.
              </>
            ) : (
              <>
                {lane.runs} successful run{lane.runs === 1 ? "" : "s"} all on{" "}
                <code className="font-mono">{lane.commit_sha}</code>
                {lane.since ? <> since {lane.since.slice(0, 10)}</> : null}, while the
                repository moved on.
              </>
            )}
          </p>

          {lane.open_findings > 0 ? (
            <p className="mt-0.5 text-[12px] text-ink-3">
              Holding {lane.open_findings} finding
              {lane.open_findings === 1 ? "" : "s"} open. A lane covering a stale tree
              cannot close a finding fixed on the tree it is not reading.
            </p>
          ) : null}

          <a
            href={`/repos/${encodeURIComponent(lane.repo_full_name)}/ci`}
            className="mt-1 inline-block font-mono text-[11px] text-ink-3 underline decoration-rule underline-offset-2 hover:text-ink"
          >
            Open the lane &rarr;
          </a>
        </div>
      ))}
    </div>
  );
}
