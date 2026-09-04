import Link from "next/link";

import { WorklistKeys } from "@/components/worklist";

import {
  EmptyState,
  ErrorPanel,
  Label,
  Pill,
  RelativeTime,
  StatTile,
} from "@/components/primitives";
import type { PullRequestRow } from "@/lib/api";
import { getPullRequests } from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * Checks, as counts rather than a verdict.
 *
 * "2 failed" and "all green" are different questions to somebody deciding
 * whether to merge, and a single tick throws away the one that decides
 * whether they look closer. A null summary is its own answer: the call
 * failed, which is not the same as a repo having no checks.
 */
function Checks({ checks }: { checks: PullRequestRow["checks"] }) {
  if (checks === null || checks === undefined) {
    return (
      <span className="text-ink-3" title="Could not read check runs from GitHub">
        unknown
      </span>
    );
  }
  if (checks.total === 0) return <span className="text-ink-3">none</span>;
  if (checks.failed > 0) {
    return <span className="font-semibold text-critical">{checks.failed} failed</span>;
  }
  if (checks.pending > 0) {
    return <span className="text-high">{checks.pending} running</span>;
  }
  return <span className="text-pass">{checks.passed} passed</span>;
}

export default async function PullRequestsPage({
  searchParams,
}: {
  searchParams: Promise<{ pr?: string }>;
}) {
  const { pr: selectedNumber } = await searchParams;
  const result = await getPullRequests();

  if (!result.ok) {
    return <ErrorPanel title="Pull requests unavailable" detail={result.error} />;
  }

  const { pull_requests, unreachable } = result.data;
  const fixes = pull_requests.filter((pr) => pr.kind === "fix");
  const installs = pull_requests.filter((pr) => pr.kind === "install");
  // Everything this platform did not open. It used to be invisible here,
  // which made a page called Pull requests show nothing for a repository with
  // fifteen of them.
  const others = pull_requests.filter((pr) => pr.kind === "other");
  // Selection in the URL, like every other list on this platform, so the row
  // somebody is looking at survives a refresh and can be sent to somebody else.
  // Opens on the first pull request rather than on a sentence describing what
  // the pane would contain if you clicked something.
  const selected =
    pull_requests.find((pr) => String(pr.number) === selectedNumber) ??
    pull_requests[0];

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Pull requests</h1>
        <span className="font-mono text-[13px] text-ink-3">
          {pull_requests.length} open across the portfolio
        </span>
        <Link
          href="/"
          className="ml-auto border border-rule px-2 py-1 font-mono text-[12px] text-ink-3 hover:border-accent hover:text-accent"
        >
          portfolio view
        </Link>
      </div>

      <div className="grid grid-cols-2 gap-2 lg:grid-cols-5">
        <StatTile label="Fixes" value={fixes.length} alert={fixes.length > 0} />
        <StatTile label="Installs" value={installs.length} />
        <StatTile label="Everyone else" value={others.length} />
        <StatTile
          label="Checks failing"
          value={pull_requests.filter((pr) => (pr.checks?.failed ?? 0) > 0).length}
        />
        <StatTile
          label="Taken over"
          value={pull_requests.filter((pr) => pr.human_edited).length}
        />
      </div>

      {unreachable.length > 0 ? (
        <div className="border-l-2 border-critical bg-critical-wash px-3 py-2 text-[13px] text-ink-2">
          <strong className="text-critical">
            {unreachable.length} repositor{unreachable.length === 1 ? "y" : "ies"} could
            not be read.
          </strong>{" "}
          Anything open there is missing from this list, so treat the count above as a
          floor rather than a total.
          <ul className="mt-1 font-mono text-[12px] text-ink-3">
            {unreachable.map((row) => (
              <li key={row.repo_full_name}>
                {row.repo_full_name} — {row.reason}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {pull_requests.length === 0 ? (
        <EmptyState
          title="Nothing open"
          detail={
            <>
              Mykronos has no pull requests waiting anywhere. Enabling a capability
              opens one to install its workflow, and Patchwork opens a draft when it
              can fix a finding deterministically.
            </>
          }
        />
      ) : (
      <>
        {/* Layout option 2, as on the triage queue and the findings tab. The
            seven-column table this replaces carried a 900px minimum, which is
            wider than the pane it would have to sit in — and it truncated the
            one column worth reading, the rationale for why Mykronos opened
            the thing at all. */}
        <WorklistKeys ids={pull_requests.map((pr) => String(pr.number))} param="pr" />
        <div className="flex flex-col gap-3 lg:h-[calc(100vh-20rem)] lg:flex-row lg:gap-0">
          <div className="lg:w-[28rem] lg:shrink-0 lg:overflow-y-auto lg:border-r lg:border-rule">
            <ul className="flex flex-col">
              {pull_requests.map((pr) => {
                const on = selected?.number === pr.number;
                return (
                  <li key={`${pr.repo_full_name}#${pr.number}`}>
                    <Link
                      href={`/pull-requests?pr=${pr.number}`}
                      scroll={false}
                      aria-current={on ? "true" : undefined}
                      className={`flex flex-col gap-0.5 border-b border-rule-soft px-2.5 py-2 ${
                        on
                          ? "border-l-2 border-l-accent bg-accent-wash"
                          : "border-l-2 border-l-transparent hover:bg-paper-3"
                      }`}
                    >
                      <span className="flex flex-wrap items-baseline gap-1.5">
                        <Pill
                          tone={
                            pr.kind === "fix"
                              ? "warn"
                              : pr.kind === "install"
                                ? "accent"
                                : "muted"
                          }
                        >
                          {pr.kind === "other" ? "theirs" : pr.kind}
                        </Pill>
                        {/* Failing checks belong in the list, not the detail:
                            it is the one thing that changes whether this row is
                            worth opening at all. */}
                        {(pr.checks?.failed ?? 0) > 0 ? (
                          <span className="font-mono text-[10px] uppercase tracking-wide text-critical">
                            {pr.checks?.failed} failing
                          </span>
                        ) : null}
                        {pr.human_edited ? (
                          <span
                            className="font-mono text-[10px] uppercase tracking-wide text-high"
                            title="Somebody committed to this branch, so Patchwork has stood down"
                          >
                            taken over
                          </span>
                        ) : null}
                      </span>
                      <span className="line-clamp-3 text-[13px] leading-snug text-ink">
                        {pr.summary || pr.title}
                      </span>
                      <span className="truncate font-mono text-[11px] text-ink-3">
                        {pr.repo_full_name} #{pr.number}
                      </span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>

          <div className="min-w-0 grow lg:overflow-y-auto lg:pl-4">
            {selected ? (
              <PullRequestDetail pr={selected} />
            ) : null}
          </div>
        </div>
      </>
      )}

      <p className="max-w-prose text-[14px] leading-relaxed text-ink-3">
        <Label as="h2">Why there is no merge button</Label>
        <br />
        Every row links out rather than merging here, and that is the design
        rather than an unfinished edge. A <Pill tone="warn">fix</Pill> changes
        your application code, and &ldquo;Patchwork never merges anything&rdquo; is
        structural rather than a policy: there is no merge operation on the
        GitHub client, in either implementation, and a test fails if one
        appears. A
        platform that could merge its own proposals would have to be trusted
        differently from one that can only show them to you.{" "}
        <Pill tone="muted">install</Pill> pull requests carry only generated
        workflow YAML, but they go the same way, because the review that matters
        happens where the code lives.
      </p>

      <p className="max-w-prose text-[14px] leading-relaxed text-ink-3">
        <Label>Freshness</Label>
        <br />
        Every row is confirmed against GitHub when this page loads, not read
        from what Mykronos last recorded. A pull request merged while a webhook
        was undelivered disappears from here immediately rather than sitting in
        the list as work that no longer exists.
      </p>
    </div>
  );
}


/**
 * One pull request, with room for the reason it exists.
 *
 * The table this replaces truncated `detail` into a `max-w` cell with the full
 * text in a `title` attribute — so the installer's plan and Patchwork's
 * rationale, the two things that explain why the platform opened something
 * against your code, were visible only on hover to somebody who knew to hover.
 */
function PullRequestDetail({ pr }: { pr: PullRequestRow }) {
  return (
    <article className="flex flex-col gap-3 border border-rule bg-paper-2 p-3">
      <div className="flex flex-col gap-1">
        <span className="flex flex-wrap items-baseline gap-2">
          <Pill tone={pr.kind === "fix" ? "warn" : pr.kind === "install" ? "accent" : "muted"}>
            {pr.kind === "other" ? "theirs" : pr.kind}
          </Pill>
          {pr.draft ? <Pill tone="muted">draft</Pill> : null}
          {pr.human_edited ? <Pill tone="warn">taken over</Pill> : null}
        </span>
        <h2 className="text-[13px] font-semibold leading-snug">{pr.title}</h2>
        <a
          href={pr.url}
          className="font-mono text-[12px] text-accent hover:underline"
          target="_blank"
          rel="noreferrer"
        >
          {pr.repo_full_name} #{pr.number} ↗
        </a>
      </div>

      {pr.summary || pr.detail ? (
        <div className="flex flex-col gap-1">
          <Label>Why this exists</Label>
          {pr.summary ? (
            <p className="text-[14px] leading-relaxed text-ink">{pr.summary}</p>
          ) : null}
          {/* Was a `title` attribute on a truncated cell. It is the platform's
              own account of what it proposed and why; it gets to be read. */}
          {pr.detail ? (
            <p className="max-w-prose text-[14px] leading-relaxed text-ink-2">{pr.detail}</p>
          ) : null}
        </div>
      ) : (
        <p className="text-[14px] leading-relaxed text-ink-3">
          Mykronos did not open this one, so it has no rationale to offer —
          only what GitHub reports about it.
        </p>
      )}

      <div className="flex flex-col gap-1">
        <Label>Checks</Label>
        {/* Counts rather than a verdict, for the reason this page has always
            given: "2 failed" and "all green" are different questions to
            somebody deciding whether to merge, and a single tick throws away
            the one that decides whether they look closer. */}
        <Checks checks={pr.checks} />
      </div>

      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-t border-rule-soft pt-2 font-mono text-[11px] text-ink-3">
        <span>
          opened <RelativeTime value={pr.opened_at} />
        </span>
        {pr.branch ? <span>{pr.branch}</span> : null}
        {/* Absent from the listing endpoint by design — one call per repository
            instead of one per pull request — so this says so rather than
            rendering a confident zero. */}
        <span>
          {pr.changed_files != null ? `${pr.changed_files} files` : "file count not fetched"}
        </span>
        {pr.capabilities?.length ? <span>{pr.capabilities.join(", ")}</span> : null}
      </div>
    </article>
  );
}
