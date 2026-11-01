/**
 * Which nav item is "you are here" (TheHub #61135, P5).
 *
 * Pure, so the vitest suite runs it. The longest matching item wins, so a
 * child entry (`/briefing/weekly`) beats its parent (`/briefing`), and a
 * section stays lit on its own sub-pages. `/` matches only itself, or every
 * page would be Portfolio. An item's query and hash are ignored: the rail
 * marks a page, not a tab.
 */
/**
 * Pages that live under one section's path and belong to another item. An
 * approval packet's URL is `/product-owner/review-queue/<id>`, and the nav's
 * home for it is Approvals (TheHub #61137). An alias applies only when its
 * item is in the nav.
 */
const ALIASES: readonly [prefix: string, href: string][] = [
  ["/product-owner/review-queue", "/approvals"],
];

export function activeHref(pathname: string, hrefs: readonly string[]): string | null {
  for (const [prefix, href] of ALIASES) {
    const under = pathname === prefix || pathname.startsWith(`${prefix}/`);
    if (under && hrefs.includes(href)) return href;
  }
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
