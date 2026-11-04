/**
 * The Ctrl+K jump box's behaviour (TheHub #60976), as pure data.
 *
 * Every keystroke the box handles is an action here and every screen it can
 * show is a state, so the component is a thin binding of this reducer to the
 * DOM and the vitest suite can drive open -> type -> select -> navigate
 * without a browser.
 */

import type { paths } from "./api-types";

export type JumpSearch =
  paths["/api/dashboard/search"]["get"]["responses"]["200"]["content"]["application/json"];
export type JumpResult = JumpSearch["results"][number];

/** Fewer characters than this is a 400 from the backend, so it is never sent. */
export const MIN_QUERY = 2;

export type JumpState = {
  open: boolean;
  query: string;
  results: JumpResult[];
  /** Index into `results`; -1 when there is nothing to choose. */
  active: number;
  loading: boolean;
  error: string | null;
  /** Set by `choose`: the href the component should navigate to, once. */
  navigateTo: string | null;
};

export type JumpAction =
  | { type: "open" }
  | { type: "close" }
  | { type: "toggle" }
  | { type: "type"; query: string }
  | { type: "results"; query: string; results: JumpResult[] }
  | { type: "failed"; query: string; error: string }
  | { type: "move"; by: 1 | -1 }
  | { type: "hover"; index: number }
  | { type: "choose"; index?: number }
  | { type: "navigated" };

export const INITIAL: JumpState = {
  open: false,
  query: "",
  results: [],
  active: -1,
  loading: false,
  error: null,
  navigateTo: null,
};

export function searchable(query: string): boolean {
  return query.trim().length >= MIN_QUERY;
}

export function jumpReducer(state: JumpState, action: JumpAction): JumpState {
  switch (action.type) {
    case "open":
      // Reopening starts clean: last time's results under a new query read
      // as answers to it.
      return { ...INITIAL, open: true };
    case "close":
      return { ...INITIAL, navigateTo: state.navigateTo };
    case "toggle":
      return state.open ? jumpReducer(state, { type: "close" }) : jumpReducer(state, { type: "open" });
    case "type":
      return {
        ...state,
        query: action.query,
        loading: searchable(action.query),
        error: null,
        ...(searchable(action.query) ? {} : { results: [], active: -1 }),
      };
    case "results":
      // An answer to a query the person has since typed past is dropped:
      // a slow reply must not replace a fast one.
      if (action.query !== state.query) return state;
      return {
        ...state,
        results: action.results,
        active: action.results.length ? 0 : -1,
        loading: false,
        error: null,
      };
    case "failed":
      if (action.query !== state.query) return state;
      return { ...state, results: [], active: -1, loading: false, error: action.error };
    case "move": {
      const n = state.results.length;
      if (!n) return state;
      return { ...state, active: (state.active + action.by + n) % n };
    }
    case "hover":
      if (action.index < 0 || action.index >= state.results.length) return state;
      return { ...state, active: action.index };
    case "choose": {
      const index = action.index ?? state.active;
      const chosen = state.results[index];
      if (!chosen) return state;
      return { ...INITIAL, navigateTo: chosen.href };
    }
    case "navigated":
      return { ...state, navigateTo: null };
  }
}

/** The parts of a KeyboardEvent the box reads. */
export type KeyLike = {
  key: string;
  ctrlKey?: boolean;
  metaKey?: boolean;
  altKey?: boolean;
  shiftKey?: boolean;
};

/** Ctrl+K on Windows and Linux, Cmd+K on a Mac, anywhere on the page. */
export function isJumpShortcut(event: KeyLike): boolean {
  return (
    (event.key === "k" || event.key === "K") &&
    Boolean(event.ctrlKey || event.metaKey) &&
    !event.altKey &&
    !event.shiftKey
  );
}

/** What a key pressed inside the open box does, or null to let it through. */
export function keyAction(event: KeyLike): JumpAction | null {
  switch (event.key) {
    case "ArrowDown":
      return { type: "move", by: 1 };
    case "ArrowUp":
      return { type: "move", by: -1 };
    case "Enter":
      return { type: "choose" };
    case "Escape":
      return { type: "close" };
    default:
      return null;
  }
}

export const LISTBOX_ID = "jump-box-results";

export function optionId(index: number): string {
  return `jump-box-option-${index}`;
}

/** The backend's own route, through this server's proxy (the token stays here). */
export function searchUrl(query: string): string {
  return `/api/search?${new URLSearchParams({ q: query.trim(), limit: "20" })}`;
}

export const KIND_LABEL: Record<JumpResult["kind"], string> = {
  repo: "Repo",
  finding: "Finding",
  cve: "CVE",
  page: "Page",
};
