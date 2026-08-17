/**
 * Where this repository is built and scanned (spec 10 §2.2, spec 15 §4a).
 *
 * A link, not a mirror. Concourse's own UI is the authority on its state, and
 * restating a build outcome here would create a second version of it to
 * disagree with. What this adds is knowing *which* pipeline, from a page
 * already about this repository — which until now meant knowing by heart.
 *
 * Both rows are indicator lights with the state written next to them. The
 * distinction they exist to keep visible: a stage nobody enabled and a stage
 * that is enabled and not answering render as the same absence everywhere
 * else, and only one of them is a problem.
 *
 * The panel also distinguishes "no pipeline covers this repo" from "Concourse
 * did not answer". Those look identical if you only render an absence, and a
 * coverage gap and an outage need entirely different responses.
 */

import {
  IndicatorLegend,
  IndicatorLight,
  Label,
  Pill,
  RelativeTime,
  Section,
  type IndicatorTone,
} from "@/components/primitives";
import type { CiJob, CiPage, CiReporting, CiStage } from "@/lib/api";

/** Concourse's vocabulary, mapped to the palette the rest of the app uses. */
function jobTone(status: string | null | undefined): IndicatorTone {
  if (status === "succeeded") return "ok";
  if (status === "failed" || status === "errored") return "bad";
  if (status === "aborted") return "warn";
  // Null is a job that has never finished a build. Not a failure — nothing
  // has happened yet, and colouring it red would invent an incident.
  return "idle";
}

export function PipelineLinks({ ci }: { ci: CiPage }) {
  const failing = ci.failing ?? [];
  return (
    <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 border border-rule bg-paper-2 px-3 py-2">
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
  );
}

/**
 * Every stage the platform covers, against what this repository has (PIP-6).
 *
 * `no_job` is the loudest state here because nothing else in the platform will
 * ever mention it: the repository believes it is covered and no job disagrees,
 * because no job exists.
 */
export function StageLights({ stages }: { stages: CiStage[] }) {
  if (stages.length === 0) {
    return (
      <p className="px-3 py-2 text-[11px] text-ink-3">
        No stage coverage has been worked out for this repository yet.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-2 px-3 py-2">
      <ul className="flex flex-wrap gap-x-4 gap-y-1.5">
        {stages.map((stage) => (
          <IndicatorLight
            key={stage.stage}
            tone={stageTone(stage)}
            label={stage.stage}
            state={stageState(stage)}
            title={stage.problem ? `${stage.stage} — ${stage.problem}` : undefined}
          />
        ))}
      </ul>
      <IndicatorLegend
        entries={[
          { tone: "ok", meaning: "reporting, or event-driven and enabled" },
          { tone: "bad", meaning: "enabled, no job or never reported" },
          { tone: "warn", meaning: "enabled, gone quiet" },
          { tone: "idle", meaning: "enabled, not run yet" },
          { tone: "off", meaning: "not enabled" },
        ]}
      />
    </div>
  );
}

/**
 * Exported so anything else asking "is this capability healthy" — the
 * enable/disable buttons in `capability-manager.tsx` among them — reads the
 * same five colours off the same states, rather than a second copy of this
 * mapping drifting from this one.
 */
export function stageTone(stage: CiStage): IndicatorTone {
  if (stage.state === "reporting") return "ok";
  // Enabled and not answering.
  if (stage.state === "no_job" || stage.state === "never_reported") return "bad";
  if (stage.state === "silent") return "warn";
  if (stage.state === "not_run") return "idle";
  // Aegis/Oracle/Patchwork (spec 10 §9, ci.py NON_SCANNING): enabled, and
  // correctly producing no ScanRun at all. This used to fall through to the
  // same "off" tone as "not enabled", which told an operator a working
  // event-driven capability was switched off. It is switched on and doing
  // exactly what it should.
  if (stage.state === "event_driven") return "ok";
  // Not enabled, which is not a fault.
  return "off";
}

export function stageState(stage: CiStage): string {
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
    case "event_driven":
      return "event-driven";
    default:
      return "off";
  }
}

/** The jobs the pipeline actually runs, each linking to its own build. */
export function JobLights({ ci }: { ci: CiPage }) {
  const jobs = ci.jobs ?? [];

  if (ci.unavailable) {
    return (
      <p className="px-3 py-2 text-[11px] leading-relaxed text-ink-3">{ci.unavailable}</p>
    );
  }
  if (jobs.length === 0) {
    return <p className="px-3 py-2 text-[11px] text-ink-3">This pipeline has no jobs.</p>;
  }

  return (
    <div className="flex flex-col gap-2 px-3 py-2">
      <ul className="flex flex-wrap gap-x-4 gap-y-1.5">
        {jobs.map((job) => (
          <JobLight key={job.name} job={job} />
        ))}
      </ul>
      <IndicatorLegend
        entries={[
          { tone: "ok", meaning: "last build succeeded" },
          { tone: "bad", meaning: "failed or errored" },
          { tone: "warn", meaning: "aborted" },
          { tone: "idle", meaning: "never finished a build" },
        ]}
      />
    </div>
  );
}

function JobLight({ job }: { job: CiJob }) {
  return (
    <IndicatorLight
      tone={jobTone(job.status)}
      label={job.name}
      state={`${job.status ?? "not run"}${job.build_name ? ` #${job.build_name}` : ""}`}
      href={job.build_url ?? undefined}
      title={job.finished_at ? `${job.name} — finished ${job.finished_at}` : undefined}
    />
  );
}

/**
 * Whether each scanning job's results actually reached the lake.
 *
 * The failure this makes visible: a pipeline is green, the dashboard shows an
 * old scan, and nothing anywhere points out that those two facts contradict
 * each other. Only the problems are listed — a row per healthy capability
 * would bury the one that matters.
 */
export function ReportingGaps({ reporting }: { reporting: CiReporting[] }) {
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

/**
 * Stage coverage and job status, without the links row.
 *
 * Split out so the Harness tab (spec 17 §2.2) can render this below a
 * `PipelineLinks` that's already rendered once, at the top of the repo page
 * (spec 17 §2.3) — rendering `PipelineLinks` a second time inside the tab
 * would say the same two links twice on one page load.
 */
export function PipelineCoverage({ ci }: { ci: CiPage }) {
  return (
    <>
      <Section title="Pipeline stages" detail="coverage of the standard set of checks">
        <StageLights stages={ci.stages ?? []} />
        <ReportingGaps reporting={ci.reporting ?? []} />
      </Section>
      <Section title="Enabled jobs" detail={ci.pipeline ?? "no Concourse pipeline"}>
        <JobLights ci={ci} />
      </Section>
    </>
  );
}

/**
 * The links and both light rows, as the dashboard lays them out.
 *
 * One definition rather than one per page: two copies of "which sections, in
 * which order, under which headings" is two things to keep in step, and the
 * one that drifts is always the one nobody is looking at.
 */
export function PipelinesPanel({ ci }: { ci: CiPage }) {
  return (
    <>
      <PipelineLinks ci={ci} />
      <PipelineCoverage ci={ci} />
    </>
  );
}
