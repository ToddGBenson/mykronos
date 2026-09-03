"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useTransition } from "react";

/**
 * A filter as a dropdown rather than a row of chips.
 *
 * The chips were not wrong — every filter they set composes correctly, and
 * they stay in the URL so a filtered view is shareable. They stop scaling at
 * about six options: the triage queue offers thirteen capabilities and five
 * severities on one line, and the eye has to read all eighteen to find out
 * which one is on.
 *
 * Three things this keeps from the chips, because losing any of them would be
 * a worse trade than the one it is making:
 *
 * **The URL is still the state.** Selecting pushes a new query string, so a
 * filtered view is still a link somebody can send. Nothing is held in
 * component state that the address bar does not also hold.
 *
 * **Every other filter survives.** The chips built their href from the whole
 * query; this reads `useSearchParams` and rewrites one key, so choosing a
 * severity cannot silently drop the capability somebody already picked.
 *
 * **Clearing is one action, not a hunt.** "Any" is the first option and sets
 * the parameter to absent rather than to an empty string — an empty string in
 * the URL reads to the backend as a filter for the empty severity.
 */
export function FilterSelect({
  label,
  name,
  value,
  options,
  anyLabel = "Any",
  clears,
}: {
  label: string;
  /** The query-string key this control owns. */
  name: string;
  /** Current value, or undefined for unfiltered. */
  value: string | undefined;
  options: readonly { value: string; label: string; hint?: string }[];
  /** What the unfiltered choice is called — "Any severity" reads better than
   *  a bare "Any" when several of these sit in a row. */
  anyLabel?: string;
  /** Other keys to drop when this one changes. The findings view selects a
   *  group and an occurrence by id; both name rows that a new filter may not
   *  return, and a detail pane describing a row that is no longer in the list
   *  is worse than an empty one. */
  clears?: readonly string[];
}) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [pending, startTransition] = useTransition();

  function choose(next: string) {
    const query = new URLSearchParams(params.toString());
    if (next) {
      query.set(name, next);
    } else {
      query.delete(name);
    }
    // Paging is a position in a filtered list. Changing the filter changes the
    // list, so the old position means nothing and keeping it lands people on
    // an empty page that looks like "no results".
    query.delete("page");
    for (const key of clears ?? []) query.delete(key);
    const search = query.toString();
    startTransition(() => router.push(search ? `${pathname}?${search}` : pathname));
  }

  const active = value !== undefined && value !== "";

  return (
    <label className="flex items-center gap-1.5">
      <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-ink-3">
        {label}
      </span>
      <select
        value={value ?? ""}
        disabled={pending}
        onChange={(event) => choose(event.target.value)}
        className={`border bg-paper px-1.5 py-0.5 font-mono text-[12px] focus:border-accent focus:outline-none disabled:opacity-50 ${
          active ? "border-accent text-accent" : "border-rule text-ink-2"
        }`}
      >
        <option value="">{anyLabel}</option>
        {options.map((entry) => (
          <option key={entry.value} value={entry.value} title={entry.hint}>
            {entry.label}
          </option>
        ))}
      </select>
    </label>
  );
}
