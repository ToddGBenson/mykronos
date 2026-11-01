/**
 * The status scale (TheHub #61135, v2 palette).
 *
 * Pure data, so the board, the run sheet and the Risk page all draw a state
 * the same way, and the vitest suite can hold it to "colour, icon and word".
 * The first six are the board's tile states; the rest are the run sheet's
 * step states. `token` names a `--color-*` in `app/globals.css`.
 */

export const STATUS_ORDER = [
  "healthy",
  "failing",
  "stale",
  "never",
  "accepted",
  "overdue",
  "ready",
  "waiting",
  "blocked",
  "done",
] as const;

export type Status = (typeof STATUS_ORDER)[number];

export type StatusIcon = "tick" | "cross" | "clock" | "ring" | "shield" | "triangle" | "dot";

export const STATUS: Record<Status, { word: string; icon: StatusIcon; token: string }> = {
  healthy: { word: "healthy", icon: "tick", token: "ok" },
  failing: { word: "failing", icon: "cross", token: "fail" },
  stale: { word: "stale or silent", icon: "clock", token: "stale" },
  never: { word: "never scanned", icon: "ring", token: "ink-3" },
  accepted: { word: "accepted", icon: "shield", token: "accepted" },
  overdue: { word: "overdue", icon: "triangle", token: "warn" },
  ready: { word: "ready for you", icon: "dot", token: "ready" },
  waiting: { word: "waiting", icon: "clock", token: "stale" },
  blocked: { word: "blocked", icon: "cross", token: "fail" },
  done: { word: "done", icon: "tick", token: "ok" },
};
