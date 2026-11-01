/**
 * Why a failing CI job failed, as one short block of text (TheHub #60913).
 *
 * The backend reads the reason (`ci_why.py`): the failed step, its exit
 * code, and the error lines the job itself raised. This turns that into the
 * lines the CI view prints under the job, so the wording — "reason
 * unavailable: …" included — is decided once and tested here.
 */
import type { CiJob } from "@/lib/api";

export type CiWhy = NonNullable<CiJob["why"]>;

export type CiRecent = NonNullable<CiJob["recent"]>;

export type WhyLines = {
  /** "Step `scan` exited 2", or "reason unavailable: …". */
  headline: string;
  /** The job's own error lines, at most three. */
  messages: string[];
  /** A caveat about what is shown, if the backend gave one. */
  note: string | null;
  /** Where the full build is. */
  url: string | null;
  source: string;
};

export function whyLines(why: CiWhy): WhyLines {
  const source = why.source === "github" ? "GitHub Actions" : "Concourse";
  if (why.unavailable) {
    return {
      headline: `reason unavailable: ${why.unavailable}`,
      messages: [],
      note: null,
      url: why.url ?? null,
      source,
    };
  }
  const step = why.step ? `Step ${why.step}` : "A step";
  const exit =
    why.exit_code === null || why.exit_code === undefined
      ? "failed"
      : `exited ${why.exit_code}`;
  return {
    headline: `${step} ${exit}`,
    messages: (why.messages ?? []).slice(0, 3),
    note: why.note ?? null,
    url: why.url ?? null,
    source,
  };
}

/**
 * The recent record printed beside the reason: "3 of last 10 failed", read
 * from the job's own finished builds. A first red build and a tenth in a row
 * call for different responses, and the reason alone cannot tell them apart.
 */
export function recentLine(recent: CiRecent | null | undefined): string | null {
  if (!recent) return null;
  if (recent.unavailable) return `recent record unavailable: ${recent.unavailable}`;
  return `${recent.failed} of last ${recent.of} failed`;
}

/** The failing jobs that carry a reason, in the order the page lists jobs. */
export function failuresWithWhy(jobs: CiJob[]): Array<CiJob & { why: CiWhy }> {
  return jobs.filter((job): job is CiJob & { why: CiWhy } => job.status === "failed" && !!job.why);
}
