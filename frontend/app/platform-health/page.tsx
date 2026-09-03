import { ErrorPanel, Label, Pill, Section } from "@/components/primitives";
import type { components } from "@/lib/api-types";
import { getPlatformHealth } from "@/lib/server";

export const dynamic = "force-dynamic";

type Job = components["schemas"]["JobHealthOut"];
type Dependency = components["schemas"]["DependencyHealthOut"];

const STATUS: Record<
  string,
  { tone: "pass" | "critical" | "warn" | "muted"; word: string }
> = {
  ok: { tone: "pass", word: "Running" },
  failing: { tone: "critical", word: "Failing" },
  late: { tone: "warn", word: "Late" },
  never_ran: { tone: "muted", word: "Never ran" },
  unknown: { tone: "muted", word: "Unknown" },
};

/**
 * What each job's silence would cost.
 *
 * The status alone says a job stopped; this says why anybody should care. A
 * health page that lists nine job names and a colour asks the reader to
 * already know which ones matter — which is exactly the knowledge somebody
 * looking at it for the first time does not have.
 */
const CONSEQUENCE: Record<string, string> = {
  absences:
    "Findings stop closing. Every count on every page drifts wrong in the reassuring direction.",
  acceptances:
    "An acceptance past its review date stays accepted, and one whose vendor shipped a fix is never re-opened.",
  governance: "A control coming off goes unnoticed until somebody opens the panel.",
  "threat-intel": "KEV and EPSS go stale, so urgency is scored against last week's world.",
  portfolio: "Risk scores stop moving and every repository keeps yesterday's number.",
  rotation: "Ingestion tokens pass their rotation date and eventually stop being accepted.",
  installations: "A repository that removed the App still reads as onboarded.",
  "fix-verification": "A merged fix is never confirmed, so its draft pull request stays open.",
  "stale-drafts": "Superseded fix branches accumulate.",
  retention:
    "Insider-risk rows outlive their retention period, which spec 06 §9 makes normative.",
  digest: "Nobody is told anything on a schedule.",
  routing: "Findings are never routed to a tracker.",
};

function JobRow({ job }: { job: Job }) {
  const status = STATUS[job.status] ?? STATUS.unknown;
  const consequence = CONSEQUENCE[job.name];

  return (
    <div className="border-t border-rule-soft px-3 py-2.5">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="font-mono text-[13px] font-bold text-ink">{job.name}</span>
        <span className="text-[12px] text-ink-3">{job.detail}</span>
        <span className="ml-auto">
          <Pill tone={status.tone} title={`This job is ${status.word.toLowerCase()}`}>
            {status.word}
          </Pill>
        </span>
      </div>
      {/* Only where it is not running. On a healthy job this would be a
          warning about a problem the reader does not have. */}
      {consequence && job.status !== "ok" ? (
        <p className="mt-1 max-w-prose text-[12px] text-ink-2">{consequence}</p>
      ) : null}
    </div>
  );
}

function DependencyRow({ dependency }: { dependency: Dependency }) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-t border-rule-soft px-3 py-2.5">
      <span className="font-mono text-[13px] font-bold text-ink">{dependency.name}</span>
      <span className="text-[12px] text-ink-3">{dependency.detail}</span>
      <span className="ml-auto">
        <Pill tone={dependency.reachable ? "pass" : "critical"}>
          {dependency.reachable ? "Reachable" : "Unreachable"}
        </Pill>
      </span>
    </div>
  );
}

/**
 * Is the platform itself working?
 *
 * It tells four repositories what is wrong with them and had no page saying
 * whether it was running. Everything here was already being computed and went
 * to a log file nobody tails.
 */
export default async function PlatformHealthPage() {
  const result = await getPlatformHealth();
  if (!result.ok) {
    return <ErrorPanel title="Platform health unavailable" detail={result.error} />;
  }
  const { degraded, jobs, dependencies, note } = result.data;

  return (
    <div className="flex flex-col gap-4">
      <header className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-lg font-bold tracking-tight">Platform health</h1>
        <Pill tone={degraded ? "critical" : "pass"}>
          {degraded ? "Needs attention" : "Healthy"}
        </Pill>
        <p className="max-w-prose text-[13px] text-ink-2">
          This platform reports on four repositories. This page is the one that
          reports on it.
        </p>
      </header>

      <Section
        title="Scheduled work"
        detail="what runs unattended, and whether it still does"
      >
        {jobs.length > 0 ? (
          jobs.map((job) => <JobRow key={job.name} job={job} />)
        ) : (
          // Distinct from every job failing. No rows means nothing has ticked
          // since this process came up, which is normal for the first minutes
          // after a deploy and alarming an hour later.
          <p className="px-3 py-2.5 text-[13px] text-ink-3">
            No job has completed a tick since this process started. Expected
            immediately after a deploy; not expected an hour later.
          </p>
        )}
      </Section>

      <Section title="Dependencies" detail="probed live on every render">
        {dependencies.length > 0 ? (
          dependencies.map((dependency) => (
            <DependencyRow key={dependency.name} dependency={dependency} />
          ))
        ) : (
          <p className="px-3 py-2.5 text-[13px] text-ink-3">
            The self-check did not complete. The job rows above still stand.
          </p>
        )}
      </Section>

      <div className="border border-rule bg-paper-2 px-3 py-2.5">
        <Label>Why this page exists</Label>
        <p className="mt-1 max-w-prose text-[12px] text-ink-2">{note}</p>
      </div>
    </div>
  );
}
