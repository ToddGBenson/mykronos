/**
 * The Today run sheet (TheHub #61141, P1 and P6).
 *
 * The server computes decide, merge, deploy and tasks
 * (`GET /api/dashboard/today`, `backend/mykronos/runsheet.py`), with a
 * reason and an owner on every line. Watch, the red and silent lanes, is the
 * briefing's own data, shaped here into the same step. Everything here is
 * pure, so the page's words are tested rather than read.
 */

import type { components } from "./api-types";

export type RunSheet = components["schemas"]["RunSheetOut"];
/** A line. `sha` is a pull request's or main's head (#61142); the Watch lines have none. */
export type ItemLike = Omit<components["schemas"]["RunSheetItemOut"], "sha"> & { sha?: string };
export type StepLike = Omit<components["schemas"]["RunSheetStepOut"], "key" | "items"> & {
  key: string;
  items: ItemLike[];
};
export type RunState = StepLike["state"];

/** Every state is a colour, an icon and a word; colour never carries it alone. */
export const STATE_META: Record<RunState, { word: string; icon: string; tone: string }> = {
  ready: { word: "ready for you", icon: "→", tone: "accent" },
  waiting: { word: "waiting", icon: "◷", tone: "high" },
  blocked: { word: "blocked", icon: "✕", tone: "critical" },
  done: { word: "done", icon: "✓", tone: "pass" },
  unknown: { word: "not known", icon: "?", tone: "muted" },
};

export function headline(steps: StepLike[]): string {
  const count = (state: RunState) => steps.filter((s) => s.state === state).length;
  const ready = count("ready");
  const parts: string[] = [];
  if (ready) parts.push(`${ready} step${ready === 1 ? " needs" : "s need"} you`);
  const waiting = count("waiting") + count("blocked");
  if (waiting) parts.push(`${waiting} waiting`);
  const unknown = count("unknown");
  if (unknown) parts.push(`${unknown} could not be read`);
  return parts.length ? parts.join(" · ") : "nothing needs you today";
}

type Stalled = {
  repo_full_name: string;
  capability: string;
  reason: string;
  detail?: string;
  days_since_run?: number;
  open_findings: number;
};
type Stale = {
  repo_full_name: string;
  capability: string;
  reason: string;
  runs?: number;
  open_findings: number;
};

function frozen(n: number): string {
  return n > 0 ? ` · ${n} open finding${n === 1 ? "" : "s"} frozen` : "";
}

function since(days: number | undefined): string {
  if (days == null) return "";
  const hours = Math.round(days * 24);
  return hours < 48 ? `${hours}h` : `${Math.round(days)}d`;
}

/** Watch: lanes that cannot close anything, from `GET /api/dashboard/briefing`. */
export function watchStep(
  stalled: Stalled[] | null,
  stale: Stale[] | null,
  reason = "",
): StepLike {
  const base = { key: "watch", title: "Watch", hidden: [], notes: [] };
  if (stalled === null) {
    return {
      ...base,
      state: "unknown",
      summary: "the lanes could not be read",
      items: [],
      status: "unavailable",
      reason: reason || "The briefing could not be read.",
    };
  }
  const items: ItemLike[] = [
    ...stalled.map((s) => ({
      text: `${s.repo_full_name} / ${s.capability}`,
      state: (s.reason === "failing" ? "blocked" : "waiting") as RunState,
      reason:
        (s.reason === "silent"
          ? `silent ${since(s.days_since_run)}`
          : `${s.reason}${s.detail ? `: ${s.detail}` : ""}`) + frozen(s.open_findings),
      owner: "an agent",
      ref: "",
      url: "",
    })),
    ...(stale ?? []).map((s) => ({
      text: `${s.repo_full_name} / ${s.capability}`,
      state: "waiting" as RunState,
      reason: `reporting on an old commit${s.runs ? ` (${s.runs} runs)` : ""}` + frozen(s.open_findings),
      owner: "an agent",
      ref: "",
      url: "",
    })),
  ];
  const red = stalled.filter((s) => s.reason === "failing").length;
  const silent = stalled.filter((s) => s.reason === "silent").length;
  const blocked = stalled.length - red - silent;
  const parts = [
    red ? `${red} lane${red === 1 ? "" : "s"} red` : "",
    silent ? `${silent} silent` : "",
    blocked ? `${blocked} held behind another` : "",
    stale?.length ? `${stale.length} stale` : "",
  ].filter(Boolean);
  return {
    ...base,
    // Agents own the lanes: Watch is never a step that needs you.
    state: items.length ? "waiting" : "done",
    summary: parts.length ? parts.join(", ") : "every lane is running",
    items,
    status: stale === null ? "partial" : "ok",
    reason: stale === null ? "Stale lanes were not read." : "",
  };
}
