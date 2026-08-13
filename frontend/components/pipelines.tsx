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
import type { CiJob, CiPage } from "@/lib/api";

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
