/**
 * Which nav item is "you are here" (TheHub #61135, P5).
 *
 * Pure, so the vitest suite runs it. The longest matching item wins, so a
 * child entry (`/briefing/weekly`) beats its parent (`/briefing`), and a
 * section stays lit on its own sub-pages. `/` matches only itself, or every
 * page would be Portfolio. An item's query and hash are ignored: the rail
 * marks a page, not a tab.
 */
export function activeHref(pathname: string, hrefs: readonly string[]): string | null {
  let best: string | null = null;
  let bestLength = -1;
  for (const href of hrefs) {
    const path = href.split(/[?#]/)[0] || "/";
    const matches =
      path === "/"
        ? pathname === "/"
        : pathname === path || pathname.startsWith(`${path}/`);
    if (matches && path.length > bestLength) {
      best = href;
      bestLength = path.length;
    }
  }
  return best;
}
