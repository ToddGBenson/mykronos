"use client";

/**
 * Ctrl+K (Cmd+K on a Mac): go to a repo, a finding, a CVE or a page by
 * typing (TheHub #60976).
 *
 * Mounted once, from the root layout, so the shortcut works on every page. The
 * behaviour is `lib/jump-box.ts`'s reducer; this file binds it to the window's
 * keydown, the backend search (through `/api/search`, so the admin token stays
 * on this server) and the App Router.
 *
 * The keyboard pattern is the WAI-ARIA combobox-in-a-dialog one: focus stays
 * in the text box, and `aria-activedescendant` names the highlighted option,
 * so a screen reader announces it without focus leaving what is being typed.
 */

import { useRouter } from "next/navigation";
import { useEffect, useReducer, useRef, type Dispatch, type RefObject } from "react";

import {
  INITIAL,
  KIND_LABEL,
  LISTBOX_ID,
  isJumpShortcut,
  jumpReducer,
  keyAction,
  optionId,
  searchUrl,
  searchable,
  type JumpAction,
  type JumpSearch,
  type JumpState,
} from "@/lib/jump-box";

/** Long enough to skip the keystrokes of a word being typed, short enough to feel live. */
const DEBOUNCE_MS = 150;

export function JumpBoxView({
  state,
  dispatch,
  inputRef,
}: {
  state: JumpState;
  dispatch: Dispatch<JumpAction>;
  inputRef: RefObject<HTMLInputElement | null>;
}) {
  if (!state.open) return null;

  const activeId = state.active >= 0 ? optionId(state.active) : undefined;
  const status = state.error
    ? state.error
    : !searchable(state.query)
      ? "Type at least two characters: a repo name, a finding id, a CVE id or a page."
      : state.loading
        ? "Searching…"
        : state.results.length
          ? `${state.results.length} result${state.results.length === 1 ? "" : "s"}`
          : "Nothing matches.";

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-ink/40 px-4 pt-[12vh]"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) dispatch({ type: "close" });
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Jump to a repo, finding, CVE or page"
        className="w-full max-w-xl border border-rule bg-paper-2 shadow-lg"
      >
        <input
          ref={inputRef}
          type="text"
          role="combobox"
          aria-expanded={state.results.length > 0}
          aria-controls={LISTBOX_ID}
          aria-activedescendant={activeId}
          aria-autocomplete="list"
          autoComplete="off"
          spellCheck={false}
          placeholder="Jump to a repo, finding id, CVE or page"
          value={state.query}
          onChange={(event) => dispatch({ type: "type", query: event.target.value })}
          onKeyDown={(event) => {
            const action = keyAction(event);
            if (!action) return;
            event.preventDefault();
            dispatch(action);
          }}
          className="w-full border-b border-rule bg-paper-2 px-3 py-2.5 font-mono text-[14px] text-ink outline-none"
        />
        <ul
          id={LISTBOX_ID}
          role="listbox"
          aria-label="Results"
          aria-activedescendant={activeId}
          className="max-h-[50vh] overflow-y-auto"
        >
          {state.results.map((result, index) => (
            <li
              key={`${result.kind}:${result.href}`}
              id={optionId(index)}
              role="option"
              aria-selected={index === state.active}
              onMouseEnter={() => dispatch({ type: "hover", index })}
              onMouseDown={(event) => {
                // Before the input's blur, and without moving focus.
                event.preventDefault();
                dispatch({ type: "choose", index });
              }}
              className={`flex cursor-pointer items-baseline gap-3 px-3 py-2 ${
                index === state.active ? "bg-accent-wash" : ""
              }`}
            >
              <span className="w-14 shrink-0 font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
                {KIND_LABEL[result.kind]}
              </span>
              <span className="min-w-0">
                <span className="block truncate text-[14px] text-ink">{result.title}</span>
                <span className="block truncate font-mono text-[12px] text-ink-3">
                  {result.subtitle}
                </span>
              </span>
            </li>
          ))}
        </ul>
        <p role="status" className="border-t border-rule px-3 py-1.5 font-mono text-[11px] text-ink-3">
          {status}
          <span className="float-right">↑↓ to move · Enter to go · Esc to close</span>
        </p>
      </div>
    </div>
  );
}

export function JumpBox() {
  const [state, dispatch] = useReducer(jumpReducer, INITIAL);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const router = useRouter();

  // The shortcut, anywhere on the page. Captured so a page-local handler
  // (the findings filter bar, the worklist) cannot swallow it first.
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (!isJumpShortcut(event)) return;
      event.preventDefault();
      dispatch({ type: "toggle" });
    }
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, []);

  useEffect(() => {
    if (state.open) inputRef.current?.focus();
  }, [state.open]);

  useEffect(() => {
    if (!state.open || !searchable(state.query)) return;
    const query = state.query;
    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      try {
        const response = await fetch(searchUrl(query), { signal: controller.signal });
        if (!response.ok) {
          dispatch({ type: "failed", query, error: `Search failed (${response.status}).` });
          return;
        }
        const body = (await response.json()) as JumpSearch;
        dispatch({ type: "results", query, results: body.results });
      } catch {
        if (!controller.signal.aborted) {
          dispatch({ type: "failed", query, error: "Search could not reach the server." });
        }
      }
    }, DEBOUNCE_MS);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [state.open, state.query]);

  useEffect(() => {
    if (!state.navigateTo) return;
    router.push(state.navigateTo);
    dispatch({ type: "navigated" });
  }, [state.navigateTo, router]);

  return (
    <>
      <button
        type="button"
        onClick={() => dispatch({ type: "open" })}
        title="Jump to a repo, finding, CVE or page (Ctrl+K)"
        aria-keyshortcuts="Control+K Meta+K"
        className="tap whitespace-nowrap border border-rule px-1.5 py-0.5 font-mono text-[11px] lowercase tracking-[0.08em] text-ink-3 hover:border-accent hover:text-accent"
      >
        jump · ctrl k
      </button>
      <JumpBoxView state={state} dispatch={dispatch} inputRef={inputRef} />
    </>
  );
}
