"use client";

import { useSyncExternalStore } from "react";

/**
 * Light, dark, or whatever the operating system says.
 *
 * **This exists because the choice only started mattering on 2026-09-02.** A
 * nested `@theme` had been replacing the light palette at build time since the
 * frontend was written, so the app was dark for everybody regardless of their
 * settings and "which ground am I on" was not a question anybody could ask.
 * Fixing that introduced a variable without giving anybody a control over it,
 * which is how a redesign gets picked from a light specimen and delivered to a
 * dark screen.
 *
 * Three states rather than two, and `system` is the default. A toggle that
 * only knows light and dark has to guess on first load, and guessing wrong is
 * worse than following the setting somebody already made once for everything.
 */
const OPTIONS = [
  { id: "light", label: "light" },
  { id: "dark", label: "dark" },
  { id: "system", label: "system" },
] as const;

type Choice = (typeof OPTIONS)[number]["id"];

/**
 * `useSyncExternalStore` rather than `useState` + `useEffect`.
 *
 * The stored choice is client-only state the server cannot know, and the two
 * obvious approaches are both wrong: rendering it directly is a hydration
 * mismatch, and setting it from an effect is a second render after paint —
 * which `react-hooks/set-state-in-effect` objects to, correctly. This hook
 * exists for exactly this shape, and its server snapshot makes "the server
 * says system" an explicit answer rather than an accident.
 */
const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  // `storage` fires in *other* tabs, so a second window follows along rather
  // than disagreeing with the one that changed it.
  window.addEventListener("storage", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", listener);
  };
}

function getSnapshot(): Choice {
  try {
    const stored = localStorage.getItem("theme");
    return stored === "light" || stored === "dark" ? stored : "system";
  } catch {
    // Private windows and blocked site data. The page still works; it just
    // follows the OS, which is the default anyway.
    return "system";
  }
}

export function ThemeToggle() {
  const choice = useSyncExternalStore(subscribe, getSnapshot, () => "system" as Choice);

  function pick(next: Choice) {
    try {
      if (next === "system") localStorage.removeItem("theme");
      else localStorage.setItem("theme", next);
    } catch {
      // Storage refused. The attribute below still applies for this page view,
      // so the click does something rather than nothing.
    }
    if (next === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", next);
    // `storage` does not fire in the tab that wrote it.
    for (const listener of listeners) listener();
  }

  return (
    <div className="flex items-center gap-px" role="group" aria-label="Colour theme">
      {OPTIONS.map((option) => (
        <button
          key={option.id}
          type="button"
          onClick={() => pick(option.id)}
          aria-pressed={choice === option.id}
          className={`inline-flex min-h-[24px] items-center border px-2 py-0.5 font-mono text-[11px] lowercase tracking-[0.08em] ${
            choice === option.id
              ? "border-accent bg-accent-wash text-accent"
              : "border-rule text-ink-3 hover:border-accent hover:text-accent"
          }`}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}
