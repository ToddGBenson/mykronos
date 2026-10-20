/**
 * "prod N behind" (#452). Pure, so the vitest suite runs it.
 *
 * The backend's deployment-probe job compares the running revision with the
 * default branch through the GitHub compare API and stores the answer; this
 * turns that answer into a badge. Unknown is its own badge, never "at head":
 * a probe that cannot read the revision must not read as up to date.
 */

export type DeployLag = {
  status: string;
  branch?: string;
  behind_by?: number | null;
  not_on_branch?: number | null;
  deployed_revision?: string | null;
  checked_at?: string | null;
  detail?: string;
};

export type ProdLagBadge = {
  tone: "critical" | "warn" | "pass" | "muted";
  label: string;
  title: string;
};

function checked(lag: DeployLag): string {
  return lag.checked_at ? ` Checked ${lag.checked_at.slice(0, 16).replace("T", " ")} UTC.` : "";
}

/** Null when the repository has no probe: no production, nothing to say. */
export function prodLagBadge(lag: DeployLag | null | undefined): ProdLagBadge | null {
  if (!lag) return null;
  const branch = lag.branch || "its branch";
  const running = lag.deployed_revision ? lag.deployed_revision.slice(0, 10) : "an unknown revision";
  const behind = lag.behind_by ?? 0;
  const commits = (n: number) => `${n} commit${n === 1 ? "" : "s"}`;

  if (lag.status === "behind") {
    return {
      tone: "warn",
      label: `prod ${behind} behind`,
      title: `Production runs ${running}, ${commits(behind)} behind ${branch}: merged fixes in those commits are not running.${checked(lag)}`,
    };
  }
  if (lag.status === "diverged") {
    return {
      tone: "critical",
      label: `prod ${behind} behind, off ${branch}`,
      title: `Production runs ${running}, which ${branch} does not contain: ${commits(lag.not_on_branch ?? 0)} running that are not on ${branch}, and ${commits(behind)} on ${branch} that are not running.${checked(lag)}`,
    };
  }
  if (lag.status === "at_head") {
    return {
      tone: "pass",
      label: "prod at head",
      title: `Production runs ${running}, the head of ${branch}.${checked(lag)}`,
    };
  }
  return {
    tone: "muted",
    label: "prod lag unknown",
    title: `How far production is behind ${branch} is unknown: ${lag.detail || "no reason recorded"}`,
  };
}
