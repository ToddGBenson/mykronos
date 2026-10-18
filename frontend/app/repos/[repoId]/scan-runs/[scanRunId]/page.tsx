import Link from "next/link";

import { getScanRun, getScanRuns } from "@/lib/server";
import type { ReactNode } from "react";

import {
  Crumb,
  ErrorPanel,
  Label,
  Pill,
  RelativeTime,
  Section,
  SeverityText,
  StatTile,
} from "@/components/primitives";
import type { ScanRun, ScanRunTests, SeverityBucket, Severity } from "@/lib/api";
import { checkHref, exactTime, percent, runDuration, scanRunHref, shortSha } from "@/lib/checks";

export const dynamic = "force-dynamic";

export const metadata = { title: "Scan run — Mykronos" };

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function statusTone(status: string) {
  if (status === "success") return "pass" as const;
  if (status === "no_applicable_targets") return "muted" as const;
  return "critical" as const;
}

function bytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function Bucket({ bucket }: { bucket: SeverityBucket }) {
  const parts = SEVERITIES.filter((s) => bucket.by_severity[s]).map(
    (s) => `${bucket.by_severity[s]} ${s}`,
  );
  return <>{parts.length ? parts.join(" · ") : "none"}</>;
}

/**
 * One scan run (TheHub #60761): what ran, what it found against the previous
 * run on its lane, and the raw tool output it archived.
 *
 * Scan health says whether a lane works. This answers "what did this run
 * actually say", which before meant reading the archive inside the container.
 */
export default async function ScanRunPage({
  params,
}: {
  params: Promise<{ repoId: string; scanRunId: string }>;
}) {
  const { repoId, scanRunId } = await params;
  const result = await getScanRun(scanRunId);
  if (!result.ok) {
    return <ErrorPanel title="Scan run unavailable" detail={result.error} />;
  }
  const run: ScanRun = result.data;
  const lane = await getScanRuns(repoId, run.capability);
  const { changes } = run;
  const runHref = (id: string) => scanRunHref(repoId, id);
  const historyHref = checkHref(repoId, run.capability, run.job ? { job: run.job } : {});
  const sha = shortSha(run.commit_sha);
  const duration = runDuration(run.started_at, run.completed_at);

  return (
    <div className="flex flex-col gap-4">
      <div className="font-mono text-[12px] text-ink-3">
        <Crumb href="/">Portfolio</Crumb> /{" "}
        <Crumb href={`/repos/${repoId}`}>{run.repo_full_name}</Crumb> /{" "}
        <Crumb href={checkHref(repoId, run.capability)}>{run.capability} history</Crumb> /{" "}
        <span className="text-ink-2">run {run.scan_run_id}</span>
      </div>

      <header className="flex flex-col gap-1.5">
        <div className="flex flex-wrap items-baseline gap-2">
          <Pill tone={statusTone(run.scan_status)}>{run.scan_status.replace(/_/g, " ")}</Pill>
          <Pill tone="muted">{run.capability}</Pill>
          {run.branch ? <Pill tone="muted">{run.branch}</Pill> : null}
          {run.job ? <Pill tone="accent">job {run.job}</Pill> : null}
          <Link className="ml-auto font-mono text-[12px] underline" href={historyHref}>
            all {run.job ?? run.capability} runs →
          </Link>
        </div>
        <h1 className="text-xl font-semibold leading-snug">
          {run.tool_name ?? "unknown tool"} {run.tool_version ?? ""}
        </h1>
        <div className="font-mono text-[12px] text-ink-3">
          {sha && run.commit_url ? (
            <a
              className="underline decoration-dotted hover:text-accent"
              href={run.commit_url}
              target="_blank"
              rel="noreferrer"
              title={run.commit_sha ?? undefined}
            >
              commit {sha}
            </a>
          ) : sha ? (
            `commit ${sha}`
          ) : (
            "no commit recorded"
          )}
          {run.pr_number ? ` · PR #${run.pr_number}` : ""}
          {run.triggered_by ? ` · ${run.triggered_by.replace(/_/g, " ")}` : ""}
          {run.started_at ? (
            <>
              {" · started "}
              <RelativeTime value={run.started_at} />
            </>
          ) : null}
          {run.completed_at ? (
            <>
              {" · finished "}
              <RelativeTime value={run.completed_at} />
            </>
          ) : null}
          {duration ? ` · took ${duration}` : ""}
        </div>
        {run.detail ? <p className="text-[14px] text-ink-2">{run.detail}</p> : null}
      </header>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <StatTile
          label="Reported"
          value={run.finding_count ?? "—"}
          sub="what the tool submitted"
        />
        <StatTile label="New" value={changes.new.total} sub="first seen in this run" />
        <StatTile
          label="Still reported"
          value={changes.still_reported.total}
          sub="seen before, seen again"
        />
        <StatTile
          label="Not reported"
          value={changes.not_reported ? changes.not_reported.total : "—"}
          sub={
            changes.not_reported
              ? `${changes.not_reported.closed ?? 0} since closed as fixed`
              : run.observed
                ? "no previous run on this lane"
                : "run did not complete"
          }
        />
      </div>

      <Section
        title="Against the previous run"
        detail={
          run.previous_scan_run_id ? (
            <Link className="underline" href={runHref(run.previous_scan_run_id)}>
              {run.previous_scan_run_id}
            </Link>
          ) : (
            "first run on this lane"
          )
        }
        aside={
          run.next_scan_run_id ? (
            <Link className="font-mono text-[12px] underline" href={runHref(run.next_scan_run_id)}>
              next run →
            </Link>
          ) : null
        }
      >
        <div className="flex flex-col gap-1.5 px-3 py-2.5 text-[14px]">
          {!run.exact ? (
            <p className="border-l-2 border-high bg-high-wash px-2 py-1 text-[13px] text-ink-2">
              A later run exists on this lane. A finding records only its first
              and latest run, so &ldquo;still reported&rdquo; and &ldquo;not
              reported&rdquo; are lower bounds here. &ldquo;New&rdquo; is exact.
            </p>
          ) : null}
          <p>
            <Label>New</Label> <Bucket bucket={changes.new} />
          </p>
          <p>
            <Label>Still reported</Label> <Bucket bucket={changes.still_reported} />
          </p>
          <p>
            <Label>Not reported</Label>{" "}
            {changes.not_reported ? (
              <>
                <Bucket bucket={changes.not_reported} />
                <span className="text-ink-3">
                  {" "}
                  — a finding closes only after two confirming scans miss it.
                </span>
              </>
            ) : run.observed ? (
              "nothing to compare with"
            ) : (
              "not counted: a run that did not complete is not evidence of absence"
            )}
          </p>
        </div>
      </Section>

      <RunRecord run={run} />

      <Section
        title="Findings"
        detail={
          run.findings.total
            ? `${run.findings.total} first or last seen in this run, worst first`
            : "none recorded against this run"
        }
      >
        {run.findings.items.length ? (
          <div className="scroll-x">
            <table className="w-full min-w-[720px] border-collapse font-mono text-[12px]">
              <thead>
                <tr className="border-b border-rule text-left">
                  {["Severity", "Finding", "Where", "Status", ""].map((heading) => (
                    <th
                      key={heading}
                      className="whitespace-nowrap px-2 py-1.5 text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {run.findings.items.map((finding) => (
                  <tr
                    key={finding.finding_id}
                    className="border-b border-rule-soft align-baseline last:border-b-0"
                  >
                    <td className="whitespace-nowrap px-2 py-1.5">
                      <SeverityText severity={finding.severity} />
                    </td>
                    <td className="px-2 py-1.5">
                      <Link
                        className="underline hover:text-accent"
                        href={`/repos/${repoId}/findings/${encodeURIComponent(finding.finding_id)}`}
                      >
                        {finding.title}
                      </Link>
                      <span className="block text-[11px] text-ink-3">{finding.rule_id}</span>
                    </td>
                    <td className="px-2 py-1.5 text-ink-2">{findingWhere(finding)}</td>
                    <td className="whitespace-nowrap px-2 py-1.5 text-ink-2">
                      {finding.status.replace(/_/g, " ")}
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5">
                      {finding.new ? <Pill tone="accent">new</Pill> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {run.findings.truncated ? (
              <p className="border-t border-rule-soft px-3 py-2 text-[13px] text-ink-3">
                Showing the worst {run.findings.items.length} of {run.findings.total}. The{" "}
                <Link className="underline" href={`/repos/${repoId}?tab=findings`}>
                  findings tab
                </Link>{" "}
                lists them all.
              </p>
            ) : null}
          </div>
        ) : (
          <p className="px-3 py-2.5 text-[13px] text-ink-3">
            {run.finding_count
              ? `The tool reported ${run.finding_count}, but none is recorded as first or last seen in this run: a later run has seen them since.`
              : "This run recorded no findings. Test and quality lanes never do (D-046): they report a status and a count."}
          </p>
        )}
      </Section>

      {run.tests ? <TestResults tests={run.tests} /> : null}

      <Section
        title="Raw tool output"
        detail="exactly what the tool wrote, archived on ingest · withheld from viewers"
      >
        {run.raw_files.length ? (
          <ul className="flex flex-col divide-y divide-rule-soft">
            {run.raw_files.map((file) => (
              <li key={file.filename} className="flex items-baseline gap-3 px-3 py-1.5">
                <a
                  className="font-mono text-[13px] underline"
                  href={`/api/scan-runs/${encodeURIComponent(run.scan_run_id)}/raw/${encodeURIComponent(file.filename)}`}
                >
                  {file.filename}
                </a>
                <span className="font-mono text-[11px] text-ink-3">{bytes(file.bytes)}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="px-3 py-2.5 text-[13px] text-ink-3">
            Nothing archived for this run: the lane did not upload its raw
            output, or retention has since pruned it.
          </p>
        )}
      </Section>

      {lane.ok && lane.data.runs.length > 1 ? (
        <Section
          title={`Recent ${run.capability} runs`}
          aside={
            <Link className="font-mono text-[12px] underline" href={checkHref(repoId, run.capability)}>
              full history →
            </Link>
          }
        >
          <ul className="flex flex-col divide-y divide-rule-soft">
            {lane.data.runs.map((row) => (
              <li
                key={row.scan_run_id}
                className="flex flex-wrap items-baseline gap-x-3 px-3 py-1.5 font-mono text-[12px]"
              >
                {row.scan_run_id === run.scan_run_id ? (
                  <span className="font-bold">{row.scan_run_id}</span>
                ) : (
                  <Link className="underline" href={runHref(row.scan_run_id)}>
                    {row.scan_run_id}
                  </Link>
                )}
                <Pill tone={statusTone(row.scan_status)}>{row.scan_status.replace(/_/g, " ")}</Pill>
                <span className="text-ink-3">
                  {row.branch ?? ""} · {row.tool_name ?? ""} · {row.finding_count ?? 0} reported
                </span>
                {row.completed_at ?? row.started_at ? (
                  <span className="text-ink-3">
                    <RelativeTime value={(row.completed_at ?? row.started_at) as string} />
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
    </div>
  );
}

function findingWhere(finding: ScanRun["findings"]["items"][number]): string {
  if (finding.file_path) {
    return `${finding.file_path}${finding.line_start ? `:${finding.line_start}` : ""}`;
  }
  if (finding.package_name) {
    return `${finding.package_name}${finding.package_version ? `@${finding.package_version}` : ""}`;
  }
  return "—";
}

/** Every field of the ScanRun record, so nothing it holds is only in the lake. */
function RunRecord({ run }: { run: ScanRun }) {
  const rows: [string, ReactNode][] = [
    ["Run id", run.scan_run_id],
    ["Repository", run.repo_full_name],
    ["Capability", run.capability],
    ["Tool", `${run.tool_name ?? "unknown"}${run.tool_version ? ` ${run.tool_version}` : ""}`],
    ["Job", run.job ?? "not recorded"],
    ["Branch", run.branch ?? "—"],
    [
      "Commit",
      run.commit_sha ? (
        run.commit_url ? (
          <a className="underline" href={run.commit_url} target="_blank" rel="noreferrer">
            {run.commit_sha}
          </a>
        ) : (
          run.commit_sha
        )
      ) : (
        "—"
      ),
    ],
    ["Pull request", run.pr_number ? `#${run.pr_number}` : "—"],
    ["Triggered by", run.triggered_by ? run.triggered_by.replace(/_/g, " ") : "—"],
    ["Workflow run", run.github_workflow_run_id || "—"],
    ["Started", exactTime(run.started_at) ?? "—"],
    ["Finished", exactTime(run.completed_at) ?? "not finished"],
    ["Duration", runDuration(run.started_at, run.completed_at) ?? "—"],
    ["Status", run.scan_status.replace(/_/g, " ")],
    ["Reported", run.finding_count ?? "—"],
    ["Detail", run.detail ?? "—"],
    ["Line coverage", percent(run.line_coverage) ?? "not reported"],
    ["Branch coverage", percent(run.branch_coverage) ?? "not reported"],
    ["Raw output ref", run.raw_output_ref ?? "—"],
  ];
  return (
    <Section title="Run record" detail="everything the lake holds for this run">
      <dl className="grid grid-cols-1 gap-x-4 px-3 py-2.5 font-mono text-[12px] sm:grid-cols-[max-content_1fr]">
        {rows.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-ink-3">{label}</dt>
            <dd className="mb-1 break-all text-ink-2 sm:mb-0">{value}</dd>
          </div>
        ))}
      </dl>
      {run.line_coverage !== null || run.branch_coverage !== null ? (
        <p className="border-t border-rule-soft px-3 py-1.5 text-[12px] text-ink-3">
          Coverage is context, not a security metric (spec 31 §4).
        </p>
      ) : null}
    </Section>
  );
}

/** The run's archived JUnit reports, case by case. */
function TestResults({ tests }: { tests: ScanRunTests }) {
  return (
    <Section
      title="Test results"
      detail={`${tests.passed} passed · ${tests.failures} failed · ${tests.errors} errored · ${tests.skipped} skipped of ${tests.tests}`}
    >
      <div className="flex flex-col gap-2 px-3 py-2.5 text-[13px]">
        {tests.suites.length ? (
          <ul className="flex flex-col gap-0.5 font-mono text-[12px]">
            {tests.suites.map((suite, i) => (
              <li key={`${suite.file}-${suite.name ?? ""}-${i}`}>
                <span className="text-ink">{suite.name ?? "unnamed suite"}</span>
                <span className="text-ink-3">
                  {" "}
                  · {suite.tests} tests · {suite.failures} failed · {suite.errors} errored ·{" "}
                  {suite.skipped} skipped · {suite.file}
                </span>
              </li>
            ))}
          </ul>
        ) : null}

        {tests.failing.length ? (
          <div className="flex flex-col gap-1.5">
            <Label>Failing cases</Label>
            {tests.failing.map((failing, i) => (
              <div
                key={`${failing.classname ?? ""}.${failing.name}-${i}`}
                className="border-l-2 border-critical pl-2"
              >
                <p className="font-mono text-[12px]">
                  <span className="text-critical">{failing.outcome}</span>{" "}
                  <span className="text-ink">
                    {failing.classname ? `${failing.classname}.` : ""}
                    {failing.name}
                  </span>
                  {failing.suite ? <span className="text-ink-3"> · {failing.suite}</span> : null}
                </p>
                {failing.message ? <p className="text-ink-2">{failing.message}</p> : null}
                {failing.output ? (
                  <pre className="scroll-x mt-1 max-h-64 overflow-y-auto bg-paper-3 p-2 font-mono text-[11px] text-ink-2">
                    {failing.output}
                  </pre>
                ) : null}
              </div>
            ))}
            {tests.failing_truncated ? (
              <p className="text-ink-3">
                More cases failed than are listed; the raw report has them all.
              </p>
            ) : null}
            {tests.output_withheld ? (
              <p className="text-ink-3">
                Failure output is the tool&rsquo;s own text and is withheld from viewers, as the
                raw files are (spec 12 §5).
              </p>
            ) : null}
          </div>
        ) : tests.tests ? (
          <p className="text-ink-3">No case failed.</p>
        ) : null}

        {tests.unreadable.length ? (
          <p className="text-high">
            Could not read as a report: {tests.unreadable.join(", ")} (malformed, or too large to
            parse here; the raw file is below).
          </p>
        ) : null}
      </div>
    </Section>
  );
}
