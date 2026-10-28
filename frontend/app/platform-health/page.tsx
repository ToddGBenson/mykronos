import { ErrorPanel, Label, Pill, Section } from "@/components/primitives";
import type { components } from "@/lib/api-types";
import { getPlatformHealth } from "@/lib/server";

export const dynamic = "force-dynamic";

type Job = components["schemas"]["JobHealthOut"];
type Dependency = components["schemas"]["DependencyHealthOut"];
type CiStall = components["schemas"]["CiStallOut"];
type Credential = components["schemas"]["CredentialOut"];

const STATUS: Record<
  string,
  { tone: "pass" | "critical" | "warn" | "muted"; word: string }
> = {
  ok: { tone: "pass", word: "Running" },
  failing: { tone: "critical", word: "Failing" },
  late: { tone: "warn", word: "Late" },
  never_ran: { tone: "muted", word: "Never ran" },
  unknown: { tone: "muted", word: "Unknown" },
  skipped: { tone: "warn", word: "Skipped" },
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
  "premise-monitor":
    "A risk acceptance stays in force after the evidence it rests on has changed: a published port or a rising EPSS reopens nothing.",
  governance: "A control coming off goes unnoticed until somebody opens the panel.",
  "threat-model-draft":
    "Drift between what MyKronos observes and a repository's declared threat model is never proposed as a pull request.",
  "library-checks":
    "Pull requests get no library-allowlist check, so a new dependency is added without anyone seeing it is unapproved.",
  "library-facts":
    "EOL, abandoned and license-change flags on Libraries stop updating and read as unknown or out of date.",
  "threat-model-sync":
    "A change to a repository's .sdlc/threat-model.yaml never reaches the register, so scoring reads last month's threat model.",
  environment:
    "A lapsed observation keeps lowering scores, so a finding reads less severe than the evidence still supports.",
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
  "briefing-dm":
    "The 07:00 briefing DM does not arrive. The /briefing page still answers when asked.",
  "briefing-flash":
    "An exploited or critical match to something shipped waits for Monday instead of a same-day DM. The weekly page still shows it.",
  "ci-stall":
    "A Concourse whose lanes all error after a restart reads as reachable, and nobody is told it stalled.",
  "briefing-signal-filing":
    "Next-sprint candidates are not filed to TheHub's backlog. The briefing still ranks them.",
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
        {/* Not configured is not unreachable (B-014): a deployment without
            the dependency has nothing to fail, and does not degrade the page. */}
        {dependency.configured === false ? (
          <Pill tone="muted">Not configured</Pill>
        ) : (
          <Pill tone={dependency.reachable ? "pass" : "critical"}>
            {dependency.reachable ? "Reachable" : "Unreachable"}
          </Pill>
        )}
      </span>
    </div>
  );
}

const STALL: Record<string, { tone: "pass" | "critical" | "muted"; word: string }> = {
  red: { tone: "critical", word: "Stalled" },
  green: { tone: "pass", word: "Not stalled" },
  unknown: { tone: "muted", word: "Unknown" },
};

function utc(iso: string): string {
  return `${iso.slice(0, 16).replace("T", " ")} UTC`;
}

/**
 * Concourse is stalled (TheHub #60975): many lanes errored together, which is
 * a dead worker or a sealed Vault after a restart, not the lanes themselves.
 * A reachable Concourse whose builds all error reads healthy everywhere else.
 */
function CiStallRow({ stall }: { stall: CiStall }) {
  const status = STALL[stall.status] ?? STALL.unknown;
  const red = stall.status === "red";
  return (
    <div className="border-t border-rule-soft px-3 py-2.5" data-testid="ci-stall">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="font-mono text-[13px] font-bold text-ink">ci_stall</span>
        <span className="text-[12px] text-ink-3">{stall.detail}</span>
        <span className="ml-auto">
          <Pill tone={status.tone} title={`Concourse is ${status.word.toLowerCase()}`}>
            {status.word}
          </Pill>
        </span>
      </div>
      {red ? (
        <>
          <ul className="mt-1.5 flex flex-col gap-0.5 font-mono text-[12px] text-ink-2">
            {stall.jobs.map((job) => (
              <li key={`${job.pipeline}/${job.job}`}>
                {job.url ? (
                  <a className="underline" href={job.url}>
                    {job.pipeline}/{job.job}
                  </a>
                ) : (
                  `${job.pipeline}/${job.job}`
                )}{" "}
                errored, started {utc(job.started_at)}
              </li>
            ))}
          </ul>
          <ol className="mt-1.5 list-decimal pl-5 text-[12px] text-ink">
            {stall.checklist.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          <p className="mt-1 text-[12px] text-ink-3">
            {stall.notified_at
              ? `Notified ${utc(stall.notified_at)}.`
              : "Not yet notified: the ci-stall job row says why."}
          </p>
        </>
      ) : null}
    </div>
  );
}

/**
 * What each credential state asks of the operator (TheHub #60974).
 *
 * Owned by the page, not taken from the response: the one sentence this
 * section must never print is "rotate" against an unverified token, because
 * rotating a token whose stored copy works is how a repository goes dark
 * (D-097). Only `due` is a reason to rotate.
 */
const CREDENTIAL: Record<
  string,
  { tone: "critical" | "warn" | "muted"; word: string; action: string }
> = {
  due: {
    tone: "critical",
    word: "Due",
    action:
      "rotate by hand (Concourse-scanned repos cannot receive a rotated token, D-086)",
  },
  unverified: {
    tone: "warn",
    word: "Unverified",
    action: "check that scans are arriving - do not rotate (D-097)",
  },
  expiring: {
    tone: "muted",
    word: "Expiring",
    action: "expires on its own; mint a new credential for the next run if one is needed",
  },
};

function whenDue(days: number): string {
  // An agent credential is listed only inside 24 hours (TheHub #61052), where a
  // whole-day count reads "in 0 days" or "in 1 day"; give it in hours.
  if (days > 0 && days < 1) {
    const hours = Math.max(1, Math.round(days * 24));
    return `in ${hours} ${hours === 1 ? "hour" : "hours"}`;
  }
  const whole = Math.round(Math.abs(days));
  const unit = whole === 1 ? "day" : "days";
  return days < 0 ? `${whole} ${unit} overdue` : `in ${whole} ${unit}`;
}

function CredentialRow({ credential }: { credential: Credential }) {
  const meaning = CREDENTIAL[credential.state] ?? {
    tone: "muted" as const,
    word: credential.state,
    action: "",
  };
  const date = credential.rotate_after ?? credential.expires_at ?? null;
  // State and dates only: who the credential belongs to, never the credential.
  const subject = credential.repo_full_name ?? credential.actor ?? "";

  return (
    <li
      data-credential-state={credential.state}
      className="border-t border-rule-soft px-3 py-2.5"
    >
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="font-mono text-[13px] font-bold text-ink">{subject}</span>
        <span className="text-[12px] text-ink-3">
          {/* An unverified row carries no date at all: "due <date> (N days
              overdue)" reads as a prompt to rotate, which is the one thing
              D-097 forbids for a token whose delivery is unconfirmed. */}
          {credential.state === "unverified" ? (
            "awaiting delivery confirmation"
          ) : (
            <>
              {credential.rotate_after ? "due" : "expires"}{" "}
              {date ? date.slice(0, 10) : "unknown"} ({whenDue(credential.days_until_due)})
            </>
          )}
        </span>
        <span className="ml-auto">
          <Pill tone={meaning.tone}>{meaning.word}</Pill>
        </span>
      </div>
      {meaning.action ? (
        <p className="mt-1 max-w-prose text-[12px] text-ink-2">{meaning.action}</p>
      ) : null}
    </li>
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
    return <ErrorPanel title="MyKronos Health unavailable" detail={result.error} />;
  }
  const { degraded, jobs, dependencies, note } = result.data;
  // Optional at runtime: a backend older than this page has no ci_stall.
  const stall: CiStall | undefined = result.data.ci_stall;
  const stalled = stall?.status === "red";
  // Absent from a backend older than TheHub #60974: read as none, not as an error.
  const credentials = result.data.credentials ?? [];
  const attention = `${credentials.length} ${
    credentials.length === 1 ? "credential needs" : "credentials need"
  } attention`;

  return (
    <div className="flex flex-col gap-4">
      <header className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-lg font-bold tracking-tight">MyKronos Health</h1>
        <Pill tone={degraded ? "critical" : "pass"}>
          {degraded ? "Needs attention" : "Healthy"}
        </Pill>
        <p className="max-w-prose text-[13px] text-ink-2">
          This platform reports on four repositories. This page is the one that
          reports on it.
        </p>
      </header>

      {/* A stall is the first row on the page: it explains every failing lane
          below it, and its repair comes before any of theirs. */}
      {stall && stalled ? (
        <Section title="Concourse is stalled" detail="many lanes errored together">
          <CiStallRow stall={stall} />
        </Section>
      ) : null}

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
        {stall && !stalled ? <CiStallRow stall={stall} /> : null}
      </Section>

      <Section title="Credentials" detail={attention}>
        {credentials.length > 0 ? (
          <ul>
            {credentials.map((credential) => (
              <CredentialRow
                key={`${credential.kind}:${credential.repo_full_name ?? credential.actor}`}
                credential={credential}
              />
            ))}
          </ul>
        ) : (
          <p className="px-3 py-2.5 text-[13px] text-ink-3">
            No ingestion token is past its rotation date or awaiting delivery
            confirmation, and no agent credential expires within 24 hours.
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
