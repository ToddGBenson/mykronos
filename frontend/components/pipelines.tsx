/**
 * Where this repository is built and scanned (spec 10 §2.2, spec 15 §4a).
 *
 * A link, not a mirror. The CI's own UI — Concourse's, or GitHub's Actions
 * tab — is the authority on its state, and restating a build outcome here
 * would create a second version of it to disagree with. What this adds is
 * knowing *which* pipeline, from a page already about this repository — which
 * until now meant knowing by heart.
 *
 * Both rows are indicator lights with the state written next to them. The
 * distinction they exist to keep visible: a stage nobody enabled and a stage
 * that is enabled and not answering render as the same absence everywhere
 * else, and only one of them is a problem.
 *
 * The panel also distinguishes "nothing covers this repo" from "the CI did
 * not answer". Those look identical if you only render an absence, and a
 * coverage gap and an outage need entirely different responses.
 */

import {
  INDICATOR,
  IndicatorLegend,
  Label,
  Pill,
  RelativeTime,
  type IndicatorTone,
} from "@/components/primitives";
import type { CiJob, CiPage, CiReporting, CiStage } from "@/lib/api";

/** The platform's shared build-status vocabulary, mapped to the palette the
 *  rest of the app uses. Concourse reports these words natively; GitHub's
 *  run conclusions are translated into them in `ci.py` (spec 32 §7), so this
 *  mapping serves both and neither CI leaks its own spelling into the UI. */
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
        className="font-mono text-[13px] text-accent underline-offset-2 hover:underline"
        href={ci.github_url}
        target="_blank"
        rel="noreferrer"
      >
        github.com/{ci.repo_full_name}
      </a>
      <a
        className="font-mono text-[13px] text-ink-3 underline-offset-2 hover:text-accent hover:underline"
        href={ci.github_actions_url}
        target="_blank"
        rel="noreferrer"
      >
        Actions
      </a>
      {/* Only Concourse gets a third link. An Actions-scanned repository
          reports `pipeline: "github-actions"` and a `pipeline_url` pointing
          at the same Actions tab already linked above (spec 32 §7) — showing
          it again, labelled "Concourse", would be a duplicate link and a
          false one. */}
      {ci.pipeline_url && ci.pipeline !== "github-actions" ? (
        <a
          className="font-mono text-[13px] text-accent underline-offset-2 hover:underline"
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

/**
 * The jobs the pipeline actually runs, as a tile grid (spec 18 §4) — the same
 * card idiom `ScanHealthBoxes` uses, rather than the indicator-light list this
 * replaces. Each tile links to its own build.
 */
export function JobLights({ ci }: { ci: CiPage }) {
  const jobs = ci.jobs ?? [];

  if (ci.unavailable) {
    return (
      <p className="px-3 py-2 text-[14px] leading-relaxed text-ink-3">{ci.unavailable}</p>
    );
  }
  if (jobs.length === 0) {
    return <p className="px-3 py-2 text-[13px] text-ink-3">This pipeline has no jobs.</p>;
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="grid grid-cols-2 gap-px bg-rule-soft sm:grid-cols-3 lg:grid-cols-5">
        {jobs.map((job) => (
          <JobTile key={job.name} job={job} />
        ))}
      </div>
      <div className="px-3 pb-2">
        <IndicatorLegend
          entries={[
            { tone: "ok", meaning: "last build succeeded" },
            { tone: "bad", meaning: "failed or errored" },
            { tone: "warn", meaning: "aborted" },
            { tone: "idle", meaning: "never finished a build" },
          ]}
        />
      </div>
    </div>
  );
}

function JobTile({ job }: { job: CiJob }) {
  const tone = jobTone(job.status);
  // "bg-pass border-pass" -> "border-pass": the tile's own left rule, same
  // colour vocabulary IndicatorLight uses, in ScanHealthBoxes' card shape
  // rather than its lamp-and-word one.
  const border = INDICATOR[tone].lamp.split(" ")[1];

  const body = (
    <div className={`flex flex-col gap-1 border-l-2 bg-paper-2 p-2.5 ${border}`}>
      <span className="font-mono text-[12px] text-ink-2">{job.name}</span>
      <span
        className={`font-mono text-xs font-bold uppercase tracking-[0.06em] ${INDICATOR[tone].word}`}
      >
        {job.status ?? "not run"}
      </span>
      <span className="font-mono text-[11px] leading-relaxed text-ink-3">
        {job.build_name ? `#${job.build_name}` : "no build yet"}
        {job.finished_at ? (
          <>
            {" "}
            · <RelativeTime value={job.finished_at} />
          </>
        ) : null}
      </span>
    </div>
  );

  if (!job.build_url) return body;
  return (
    <a
      href={job.build_url}
      target="_blank"
      rel="noreferrer"
      className="contents"
      title={job.finished_at ? `${job.name} — finished ${job.finished_at}` : undefined}
    >
      {body}
    </a>
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
          <li key={row.job} className="font-mono text-[12px] text-ink-2">
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
 * Job status, without the links row and without the "Pipeline stages"
 * section spec 18 §4 removes — the built/scanned-by links at the top of the
 * page and this tile grid already say whether Concourse is green, and a
 * second, differently-shaped view of the same fifteen checks added more to
 * scan than it added to know.
 *
 * Split out so the Harness tab (spec 17 §2.2) can render this below a
 * `PipelineLinks` that's already rendered once, at the top of the repo page
 * (spec 17 §2.3) — rendering `PipelineLinks` a second time inside the tab
 * would say the same two links twice on one page load.
 */

// `PipelineCoverage` and `PipelinesPanel` lived here until the Dashboard tab
// merged Scan health and Enabled jobs into one Checks section. Both were
// wrappers whose only job was to say which sections go in which order under
// which headings, and the merge is now the answer to that. `JobLights` and
// `ReportingGaps` are composed directly by the section; `PipelineLinks` is
// still used at the top of every repository tab.
//
// `PipelinesPanel` had no callers even before this — worth noting rather than
// deleting quietly, because it was the second definition of a layout that had
// drifted from the one actually rendering.
