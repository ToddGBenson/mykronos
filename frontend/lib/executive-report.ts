/**
 * The executive report's sentences, built from the summary's numbers. Pure,
 * so the vitest suite runs it.
 *
 * The headline is the one line most readers will take away, so it is derived
 * rather than written: every figure in it is a field of
 * `/api/dashboard/repos/{repo_id}/executive-summary`, and every branch below
 * is a different state of that data rather than a different tone. Above all
 * it never says "no issues" about a repository whose scanners are not
 * running: a zero from a dead lane measured nothing.
 */

export type LaneLike = {
  capability: string;
  status: string;
  blocked_by?: string;
  consecutive_failures?: number;
  stale_reason?: string;
};

export type HeadlineInput = {
  open_by_severity: Record<string, number>;
  open_total: number;
  fixability: { key: string; findings: number; serious: number }[];
  lanes: LaneLike[];
  history_since: string | null;
};

/** "1 issue", "3 issues". */
export function plural(count: number, one: string, many = `${one}s`): string {
  return `${count.toLocaleString("en-US")} ${count === 1 ? one : many}`;
}

/** A lane whose counts cannot be taken as current. */
export function laneIsDoubtful(lane: LaneLike): boolean {
  return lane.status !== "ok";
}

/** A lane that ran and has stopped working: its counts are stale. Distinct
 *  from one that never ran, which leaves a gap rather than stale numbers. */
export function laneIsStalled(lane: LaneLike): boolean {
  return lane.status !== "ok" && lane.status !== "never_ran";
}

function seriousPhrase(critical: number, high: number): string {
  const total = critical + high;
  const verb = total === 1 ? "is" : "are";
  if (critical && high) {
    return `${critical.toLocaleString("en-US")} critical and ${high.toLocaleString(
      "en-US",
    )} high-severity issues ${verb} open`;
  }
  if (critical) return `${plural(critical, "critical issue")} ${verb} open`;
  return `${plural(high, "high-severity issue")} ${verb} open`;
}

function fixPhrase(serious: number, noFix: number, fixable: number): string {
  if (noFix === serious) {
    return serious === 1
      ? "it has no fix from the vendor yet"
      : "none of them has a fix from the vendor yet";
  }
  if (noFix > 0) {
    return `${noFix.toLocaleString("en-US")} of them ${noFix === 1 ? "has" : "have"} no fix from the vendor yet`;
  }
  if (fixable === serious) {
    return serious === 1 ? "it can be fixed now" : "all of them can be fixed now";
  }
  if (fixable > 0) {
    return `${fixable.toLocaleString("en-US")} of them can be fixed now`;
  }
  return serious === 1
    ? "it needs someone to review it"
    : "each needs someone to review it";
}

/** One sentence (two at most) on the overall posture. */
export function headline(summary: HeadlineInput): string {
  if (!summary.history_since) {
    return "This repository has never been scanned, so nothing is known about its security yet.";
  }

  const critical = summary.open_by_severity.critical ?? 0;
  const high = summary.open_by_severity.high ?? 0;
  const serious = critical + high;
  const bucket = (key: string) => summary.fixability.find((b) => b.key === key);
  const doubtful = summary.lanes.filter(laneIsDoubtful).length;
  const lanes = summary.lanes.length;

  let first: string;
  if (serious > 0) {
    first = `${seriousPhrase(critical, high)}; ${fixPhrase(
      serious,
      bucket("no_vendor_fix")?.serious ?? 0,
      bucket("fixable_now")?.serious ?? 0,
    )}.`;
  } else if (summary.open_total > 0) {
    first = `No critical or high-severity issues are open; ${plural(
      summary.open_total,
      "lower-severity issue is",
      "lower-severity issues are",
    )}.`;
  } else if (doubtful > 0) {
    // The one sentence this page must never print unqualified.
    return `No security issues are open, but ${doubtful} of ${plural(
      lanes,
      "scanner",
    )} ${doubtful === 1 ? "is" : "are"} not reporting normally, so that is not yet a clean bill of health.`;
  } else {
    first = "No security issues are open.";
  }

  if (lanes === 0) {
    return `${first} No scanner is set up for this repository, so this covers nothing.`;
  }
  const stalled = summary.lanes.filter(laneIsStalled).length;
  const never = doubtful - stalled;
  if (stalled > 0) {
    return `${first} ${stalled} of ${plural(lanes, "scanner")} ${
      stalled === 1 ? "is" : "are"
    } not reporting normally, so these numbers may be out of date.`;
  }
  if (never > 0) {
    return `${first} ${never} enabled ${never === 1 ? "scanner has" : "scanners have"} never run, so ${
      never === 1 ? "its area is" : "their areas are"
    } not covered.`;
  }
  return first;
}

/** A count against an earlier one: "+12", "−5", "no change". */
export function change(now: number, then: number | null | undefined): string {
  if (then === null || then === undefined) return "—";
  const delta = now - then;
  if (delta === 0) return "no change";
  // U+2212, so a fall and a rise are the same width in a table.
  return delta > 0 ? `+${delta.toLocaleString("en-US")}` : `−${(-delta).toLocaleString("en-US")}`;
}

/** What one scanning lane's state means, without the vocabulary. */
export function laneStatusText(lane: LaneLike): string {
  switch (lane.status) {
    case "ok":
      return "Running normally";
    case "failing":
      return lane.consecutive_failures && lane.consecutive_failures > 1
        ? `Failing: the last ${lane.consecutive_failures} runs failed`
        : "Failing: the last run failed";
    case "silent":
      return "Stopped: has not run on its usual schedule";
    case "blocked":
      return lane.blocked_by
        ? `Waiting: held up because the ${lane.blocked_by} checks are failing`
        : "Waiting: held up by another failing check";
    case "not_covering":
      return lane.stale_reason === "wrong_branch"
        ? "Running, but scanning a branch that is not the main one"
        : "Running, but re-scanning an old version of the code";
    case "never_ran":
      return "Never run: enabled, but no scan has reported";
    default:
      return lane.status;
  }
}

/** One line on what each scanner looks at, for a reader who has never met one. */
export const SCANNER_GLOSS: Record<string, string> = {
  sast: "reads the source code for unsafe patterns",
  secrets: "looks for passwords and keys committed to the code",
  atlas: "checks third-party libraries against published vulnerabilities",
  containers: "checks the software packaged inside each container image",
  iac: "checks infrastructure definitions for unsafe settings",
  dast: "probes the running application from outside, as an attacker would",
  cloud: "checks the cloud account's configuration",
  network: "checks the network for exposed services",
  ai: "checks how the code uses AI models",
};

export const FIX_BUCKETS: { key: string; label: string; gloss: string }[] = [
  {
    key: "fixable_now",
    label: "Fixable now",
    gloss: "a fix is known: a newer version, a configuration change or a credential to replace",
  },
  {
    key: "needs_review",
    label: "Needs review",
    gloss: "a person has to read it and decide; some turn out to be false alarms",
  },
  {
    key: "no_vendor_fix",
    label: "Waiting on vendors",
    gloss: "the software's maker has not published a fix, so there is nothing to upgrade to yet",
  },
];

/** "18 Oct 2026, 15:13 UTC" -- absolute, because a printed page has no "now". */
export function formatWhen(value: string | null | undefined, withTime = true): string {
  if (!value) return "never";
  // Lake timestamps are naive UTC (spec 01 §6).
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(value) || value.length <= 10 ? value : `${value}Z`;
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return value;
  const date = when.toLocaleDateString("en-GB", {
    day: "numeric",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  });
  if (!withTime) return date;
  const time = when.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
  });
  return `${date}, ${time} UTC`;
}
