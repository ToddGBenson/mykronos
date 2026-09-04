"use client";

import { useEffect } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

/**
 * Keyboard movement through the queue (layout option 2).
 *
 * A split-pane worklist is only worth building if you can work it without the
 * mouse — otherwise it is a table with a bigger aside. `j`/`k` move, `Enter`
 * opens the repository the selected finding belongs to.
 *
 * Selection lives in the URL rather than in state, for the same reason every
 * other filter here does: the row somebody is looking at is part of the view,
 * so it should survive a refresh and be sendable to somebody else.
 *
 * Deliberately inert while a text field has focus. The rule/CVE search box sits
 * directly above this list, and a queue that jumps two rows because somebody
 * typed "jk" into a search field would be worse than no shortcuts at all.
 */
export function WorklistKeys({
  ids,
  param = "finding",
  clears,
}: {
  ids: string[];
  /** Which query parameter holds the selection. The triage queue selects a
   *  finding; the findings tab selects a group, because a group is the unit of
   *  the decision there and its occurrences are a level below. */
  param?: string;
  /** Parameters to drop when the selection moves. A findings group carries a
   *  chosen occurrence, and keeping it while moving to a different group would
   *  leave a disposition control pointed at a row that is no longer shown. */
  clears?: readonly string[];
}) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.metaKey || event.ctrlKey || event.altKey) return;

      const target = event.target as HTMLElement | null;
      const tag = target?.tagName;
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        target?.isContentEditable
      ) {
        return;
      }

      const current = params.get(param);
      const index = current ? ids.indexOf(current) : -1;

      let next: string | undefined;
      if (event.key === "j") next = ids[index < 0 ? 0 : Math.min(index + 1, ids.length - 1)];
      else if (event.key === "k") next = ids[index <= 0 ? 0 : index - 1];
      else return;

      if (!next || next === current) return;
      event.preventDefault();

      const query = new URLSearchParams(params.toString());
      query.set(param, next);
      for (const key of clears ?? []) query.delete(key);
      // `scroll: false` — the pane below is what changed, and yanking the page
      // to the top on every keypress makes the list unusable at speed.
      router.replace(`${pathname}?${query.toString()}`, { scroll: false });
    }

    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [ids, param, clears, params, pathname, router]);

  return null;
}
