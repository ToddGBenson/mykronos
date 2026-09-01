import Link from "next/link";

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

export default async function PullRequestsPage() {
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

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Pull requests</h1>
        <span className="font-mono text-[11px] text-ink-3">
          {pull_requests.length} open across the portfolio
        </span>
        <Link
          href="/"
          className="ml-auto border border-rule px-2 py-1 font-mono text-[10px] text-ink-3 hover:border-accent hover:text-accent"
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
        <div className="border-l-2 border-critical bg-critical-wash px-3 py-2 text-[11px] text-ink-2">
          <strong className="text-critical">
            {unreachable.length} repositor{unreachable.length === 1 ? "y" : "ies"} could
            not be read.
          </strong>{" "}
          Anything open there is missing from this list, so treat the count above as a
          floor rather than a total.
          <ul className="mt-1 font-mono text-[10px] text-ink-3">
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
        <div className="scroll-x border border-rule">
          <table className="w-full min-w-[900px] border-collapse bg-paper-2 font-mono text-[11px]">
            <thead>
              <tr className="border-b-2 border-ink-2 text-left">
                {["Kind", "Repository", "What it changes", "Files", "Checks", "Age", ""].map(
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
              {pull_requests.map((pr) => (
                <tr
                  key={`${pr.repo_full_name}#${pr.number}`}
                  className="border-b border-rule-soft last:border-b-0 align-top hover:bg-paper-3"
                >
                  <td className="whitespace-nowrap px-2 py-2">
                    <Pill tone={pr.kind === "fix" ? "warn" : pr.kind === "install" ? "accent" : "muted"}>
                      {pr.kind === "other" ? "theirs" : pr.kind}
                    </Pill>
                    {pr.draft ? (
                      <span className="ml-1 text-[9px] text-ink-3">draft</span>
                    ) : null}
                  </td>
                  <td className="max-w-[24ch] truncate px-2 py-2 text-ink">
                    {pr.repo_full_name}
                    <span className="text-ink-3"> #{pr.number}</span>
                  </td>
                  <td className="max-w-[38ch] px-2 py-2">
                    <div className="truncate text-ink" title={pr.title}>
                      {pr.summary || pr.title}
                    </div>
                    {pr.detail ? (
                      <div
                        className="mt-0.5 line-clamp-2 text-[10px] leading-snug text-ink-3"
                        title={pr.detail}
                      >
                        {pr.detail}
                      </div>
                    ) : null}
                    {pr.human_edited ? (
                      <div className="mt-1 text-[10px] text-high">
                        A person has committed here — Patchwork has stood down
                        permanently.
                      </div>
                    ) : null}
                  </td>
                  <td className="px-2 py-2 text-ink-2">{pr.changed_files ?? "—"}</td>
                  <td className="whitespace-nowrap px-2 py-2">
                    <Checks checks={pr.checks} />
                  </td>
                  <td className="whitespace-nowrap px-2 py-2 text-ink-2">
                    <RelativeTime value={pr.opened_at} />
                  </td>
                  <td className="whitespace-nowrap px-2 py-2 text-right">
                    <a
                      href={pr.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="border border-rule px-2 py-1 text-[10px] text-ink-2 hover:border-accent hover:text-accent"
                    >
                      review on GitHub →
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
        <Label>Why there is no merge button</Label>
        <br />
        Every row links out rather than merging here, and that is the design
        rather than an unfinished edge. A <Pill tone="warn">fix</Pill> changes
        your application code, and spec 08 §3 makes &ldquo;Patchwork never merges
        anything&rdquo; structural: there is no merge operation on the GitHub
        client, in either implementation, and a test fails if one appears. A
        platform that could merge its own proposals would have to be trusted
        differently from one that can only show them to you.{" "}
        <Pill tone="muted">install</Pill> pull requests carry only generated
        workflow YAML, but they go the same way, because the review that matters
        happens where the code lives.
      </p>

      <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
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
