import Link from "next/link";

import { getScanRun, getScanRuns } from "@/lib/server";
import {
  Crumb,
  ErrorPanel,
  Label,
  Pill,
  RelativeTime,
  Section,
  StatTile,
} from "@/components/primitives";
import type { ScanRun, SeverityBucket, Severity } from "@/lib/api";

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
  const runHref = (id: string) => `/repos/${repoId}/scan-runs/${encodeURIComponent(id)}`;

  return (
    <div className="flex flex-col gap-4">
      <div className="font-mono text-[12px] text-ink-3">
        <Crumb href="/">Portfolio</Crumb> /{" "}
        <Crumb href={`/repos/${repoId}`}>{run.repo_full_name}</Crumb> /{" "}
        <span className="text-ink-2">
          {run.capability} run {run.scan_run_id}
        </span>
      </div>

      <header className="flex flex-col gap-1.5">
        <div className="flex flex-wrap items-baseline gap-2">
          <Pill tone={statusTone(run.scan_status)}>{run.scan_status.replace(/_/g, " ")}</Pill>
          <Pill tone="muted">{run.capability}</Pill>
          {run.branch ? <Pill tone="muted">{run.branch}</Pill> : null}
        </div>
        <h1 className="text-xl font-semibold leading-snug">
          {run.tool_name ?? "unknown tool"} {run.tool_version ?? ""}
        </h1>
        <div className="font-mono text-[12px] text-ink-3">
          {run.commit_sha ? `commit ${run.commit_sha.slice(0, 12)}` : "no commit recorded"}
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

      <Section
        title="Raw tool output"
        detail="exactly what the tool wrote, archived on ingest · admin only"
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
        <Section title={`Recent ${run.capability} runs`}>
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
