/**
 * Where this repository is built and scanned (spec 10 §2.2, spec 15 §4a).
 *
 * A link, not a mirror. Concourse's own UI is the authority on its state, and
 * restating a build outcome here would create a second version of it to
 * disagree with. What this adds is knowing *which* pipeline, from a page
 * already about this repository — which until now meant knowing by heart.
 *
 * The panel distinguishes "no pipeline covers this repo" from "Concourse did
 * not answer". They look identical if you only render an absence, and a
 * coverage gap and an outage need entirely different responses.
 */

import { Label, Pill, RelativeTime } from "@/components/primitives";
import type { CiJob, CiPage, CiReporting, CiStage } from "@/lib/api";

/** Concourse's vocabulary, mapped to the palette the rest of the app uses. */
function jobTone(status: string | null | undefined): "critical" | "warn" | "pass" | "muted" {
  if (status === "succeeded") return "pass";
  if (status === "failed" || status === "errored") return "critical";
  if (status === "aborted") return "warn";
  // Null is a job that has never finished a build. Not a failure — nothing
  // has happened yet, and colouring it red would invent an incident.
  return "muted";
}

export function PipelinesPanel({ ci }: { ci: CiPage }) {
  const jobs = ci.jobs ?? [];
  const failing = ci.failing ?? [];

  return (
    <section className="border border-rule bg-paper-2">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 border-b border-rule-soft px-3 py-2">
        <Label>Built and scanned by</Label>
        <a
          className="font-mono text-[11px] text-accent underline-offset-2 hover:underline"
          href={ci.github_url}
          target="_blank"
          rel="noreferrer"
        >
          github.com/{ci.repo_full_name}
        </a>
        <a
          className="font-mono text-[11px] text-ink-3 underline-offset-2 hover:text-accent hover:underline"
          href={ci.github_actions_url}
          target="_blank"
          rel="noreferrer"
        >
          Actions
        </a>
        {ci.pipeline_url ? (
          <a
            className="font-mono text-[11px] text-accent underline-offset-2 hover:underline"
            href={ci.pipeline_url}
            target="_blank"
            rel="noreferrer"
          >
            Concourse: {ci.pipeline}
          </a>
        ) : null}
        {failing.length > 0 ? (
          <span className="ml-auto">
            <Pill tone="critical">
              {failing.length} failing: {failing.join(", ")}
            </Pill>
          </span>
        ) : null}
      </div>

      <StageCoverage stages={ci.stages ?? []} />

      <ReportingRow reporting={ci.reporting ?? []} />

      {ci.unavailable ? (
        <p className="px-3 py-2 text-[11px] leading-relaxed text-ink-3">
          {ci.unavailable}
        </p>
      ) : jobs.length === 0 ? (
        <p className="px-3 py-2 text-[11px] text-ink-3">
          This pipeline has no jobs.
        </p>
      ) : (
        <ul className="flex flex-wrap gap-x-4 gap-y-1.5 px-3 py-2">
          {jobs.map((job) => (
            <JobChip key={job.name} job={job} />
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * Every stage the platform covers, against what this repository has (PIP-6).
 *
 * The distinction worth the space: a stage nobody enabled and a stage that is
 * enabled and not answering both render as an absence everywhere else, and
 * only one of them is a problem. `no_job` is the one that is hardest to see
 * otherwise — the repository believes it is covered and no job disagrees,
 * because no job exists.
 */
function StageCoverage({ stages }: { stages: CiStage[] }) {
  if (stages.length === 0) return null;

  const covered = stages.filter((s) => s.state === "reporting");
  const problems = stages.filter((s) => s.problem);

  return (
    <div className="border-t border-rule-soft px-3 py-2">
      <div className="flex items-baseline gap-3">
        <Label>Stage coverage</Label>
        <span className="font-mono text-[10px] text-ink-3">
          {covered.length} of {stages.length} reporting
          {problems.length > 0 ? ` · ${problems.length} need attention` : null}
        </span>
      </div>
      <ul className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
        {stages.map((stage) => (
          <li key={stage.stage} className="flex items-baseline gap-1">
            <Pill tone={stageTone(stage)}>{stageLabel(stage)}</Pill>
            <span
              className={`font-mono text-[10px] ${
                stage.enabled ? "text-ink-2" : "text-ink-3"
              }`}
            >
              {stage.stage}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function stageTone(stage: CiStage): "critical" | "warn" | "pass" | "muted" {
  if (stage.state === "reporting") return "pass";
  // Enabled and not answering. `no_job` is the loudest of these because
  // nothing else in the platform will ever mention it.
  if (stage.state === "no_job" || stage.state === "never_reported") return "critical";
  if (stage.state === "silent") return "warn";
  // Not enabled, or enabled with no successful build yet. Neither is a fault.
  return "muted";
}

function stageLabel(stage: CiStage): string {
  switch (stage.state) {
    case "reporting":
      return "ok";
    case "no_job":
      return "no job";
    case "never_reported":
      return "never reported";
    case "silent":
      return "silent";
    case "not_run":
      return "not run";
    default:
      return "off";
  }
}

/**
 * Whether each scanning job's results actually reached the lake.
 *
 * The failure this makes visible: a pipeline is green, the dashboard shows an
 * old scan, and until now nothing anywhere pointed out that those two facts
 * contradict each other. Only the problems are listed — a row per healthy
 * capability would bury the one that matters.
 */
function ReportingRow({ reporting }: { reporting: CiReporting[] }) {
  const problems = reporting.filter(
    (row) => row.state === "silent" || row.state === "never_reported",
  );
  if (problems.length === 0) return null;

  return (
    <div className="border-t border-rule-soft bg-high-wash px-3 py-2">
      <Label>Ran, but nothing arrived</Label>
      <ul className="mt-1 flex flex-col gap-0.5">
        {problems.map((row) => (
          <li key={row.job} className="font-mono text-[10px] text-ink-2">
            <span className="font-bold">{row.job}</span> succeeded
            {row.built_at ? (
              <>
                {" "}
                <RelativeTime value={row.built_at} />
              </>
            ) : null}
            {row.state === "never_reported" ? (
              <> — no successful {row.capability} scan has ever reached the lake.</>
            ) : (
              <>
                {" "}
                — newest {row.capability} scan is from{" "}
                {row.scanned_at ? <RelativeTime value={row.scanned_at} /> : "before it"},
                so that build&rsquo;s findings never arrived.
              </>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function JobChip({ job }: { job: CiJob }) {
  const label = (
    <span className="flex items-baseline gap-1.5">
      <Pill tone={jobTone(job.status)}>{job.status ?? "not run"}</Pill>
      <span className="font-mono text-[11px]">{job.name}</span>
      {job.build_name ? (
        <span className="font-mono text-[9px] text-ink-3">#{job.build_name}</span>
      ) : null}
      {job.finished_at ? (
        <span className="font-mono text-[9px] text-ink-3">
          <RelativeTime value={job.finished_at} />
        </span>
      ) : null}
    </span>
  );

  return (
    <li>
      {job.build_url ? (
        <a
          href={job.build_url}
          target="_blank"
          rel="noreferrer"
          className="underline-offset-2 hover:underline"
        >
          {label}
        </a>
      ) : (
        label
      )}
    </li>
  );
}
