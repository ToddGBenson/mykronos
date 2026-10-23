/**
 * One cell of the portfolio's capability grid: which state it is in, how that
 * state is drawn, and the sentence that names it. Pure, so the vitest suite
 * runs it.
 *
 * A cell used to be solid green whenever its capability had EVER scanned
 * (`has_scanned`), however its last run ended — a lane failing on every build
 * still read as coverage. `failed` is the latest state: the backend's
 * `last_run_failed`, which is the last scan run not succeeding OR the lane
 * that produces the capability last failing/erroring (a job can break before
 * it uploads anything, and then no failed run is ever written). Green now
 * means the latest run worked, not that one once did.
 */

import { asUtc } from "./checks";

export type CellState = "failed" | "refused" | "reporting" | "silent" | "pending" | "off";

/** The fields of a backend `CapabilityStateOut` this cell reads. */
export type CapabilityRun = {
  capability: string;
  has_scanned: boolean;
  last_run_failed?: boolean;
  last_scan_at?: string | null;
  last_scan_status?: string | null;
  lane_ci?: "concourse" | "github_actions" | null;
  lane_pipeline?: string | null;
  lane_job?: string | null;
  lane_status?: string | null;
  lane_build_name?: string | null;
  lane_finished_at?: string | null;
  /** Uploads turned away for want of a grant (TheHub #60813). */
  refused?: boolean;
  last_refused_at?: string | null;
};

/**
 * Which of the six states a cell is in.
 *
 * `failed` applies only to an enabled capability — "not enabled" stays not
 * enabled whatever a stray lane does — but does apply to an enabled one that
 * has never written a scan: a lane failing before its first upload is
 * exactly the job that broke, and drawing it as merely silent hides that.
 *
 * `refused` is the exception that proves it (TheHub #60813): a lane is
 * running and uploading, and Mykronos turns it away because the capability
 * is not granted. That is never "enabled", by definition, so it would read as
 * "not enabled" or "silent" — the same absence as a lane that never sent
 * anything. It wins over both, because only it has findings being discarded.
 */
export function cellState({
  enabled,
  pending,
  run,
}: {
  enabled: boolean;
  pending: boolean;
  run?: CapabilityRun;
}): CellState {
  if (run?.refused) return "refused";
  if (enabled && run?.last_run_failed) return "failed";
  if (enabled && run?.has_scanned) return "reporting";
  if (enabled) return "silent";
  if (pending) return "pending";
  return "off";
}

/**
 * Fill for evidence, outline for a claim, near-nothing for absence — and a
 * failure is filled in the critical tone with a mark inside, so it is told
 * from a pass by form as well as by hue (the two solids are close in
 * greyscale).
 */
export const CELL_SKIN: Record<CellState, string> = {
  failed: "border-critical bg-critical",
  refused: "border-critical bg-transparent",
  reporting: "border-pass bg-pass",
  silent: "border-dashed border-accent bg-transparent",
  pending: "border-dotted border-accent bg-accent-wash",
  off: "border-rule bg-paper",
};

/** The legend's words for each state, in the order the legend lists them. */
export const CELL_MEANING: Record<CellState, string> = {
  reporting: "last run succeeded",
  failed: "last run failed",
  refused: "uploads refused: not granted",
  silent: "enabled, not yet reporting",
  pending: "pending install PR",
  off: "not enabled",
};

export const LEGEND_ORDER: CellState[] = [
  "reporting",
  "failed",
  "refused",
  "silent",
  "pending",
  "off",
];

/** `2026-10-20 14:03 UTC`, to the minute: what a hover needs, not a log line. */
export function minuteTime(timestamp: string | null | undefined): string | null {
  if (!timestamp) return null;
  const parsed = Date.parse(asUtc(timestamp));
  if (!Number.isFinite(parsed)) return timestamp;
  return `${new Date(parsed).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

const FAILED_LANE = new Set(["failed", "errored"]);

/** "Concourse thehub/unit #336" or "GitHub Actions sast #41". */
export function laneName(run: CapabilityRun): string | null {
  if (!run.lane_job) return null;
  const build = run.lane_build_name ? ` #${run.lane_build_name}` : "";
  if (run.lane_ci === "github_actions") return `GitHub Actions ${run.lane_job}${build}`;
  const where = run.lane_pipeline ? `${run.lane_pipeline}/${run.lane_job}` : run.lane_job;
  return `Concourse ${where}${build}`;
}

const SCAN_STATUS_WORDS: Record<string, string> = {
  failure: "failed",
  partial_failure: "partly failed",
};

/**
 * Why a failed cell is failed, in one line: the lane if the lane is what
 * failed, the scan if the scan did, both if both did.
 */
export function failureReason(run: CapabilityRun): string {
  const parts: string[] = [];
  if (run.lane_status && FAILED_LANE.has(run.lane_status)) {
    const when = minuteTime(run.lane_finished_at);
    const name = laneName(run);
    parts.push(
      `last run ${run.lane_status}${when ? ` ${when}` : ""}${name ? ` (${name})` : ""}`,
    );
  }
  const scanOk = ["success", "no_applicable_targets", "reported"];
  if (run.last_scan_status && !scanOk.includes(run.last_scan_status)) {
    const when = minuteTime(run.last_scan_at);
    const words = SCAN_STATUS_WORDS[run.last_scan_status] ?? `ended "${run.last_scan_status}"`;
    parts.push(`last scan ${words}${when ? ` ${when}` : ""}`);
  }
  return parts.length ? parts.join("; ") : "last run failed";
}

/** The state in words, as the cell's hover and accessible name say it. */
export function cellStateText(state: CellState, run?: CapabilityRun): string {
  if (state === "failed") return run ? failureReason(run) : "last run failed";
  if (state === "refused") {
    const when = minuteTime(run?.last_refused_at);
    return `uploads refused${when ? ` ${when}` : ""}: the lane is sending and the capability is not granted`;
  }
  if (state === "reporting") return "reporting, last run succeeded";
  return CELL_MEANING[state];
}
