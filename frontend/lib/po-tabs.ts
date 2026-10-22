/**
 * The tabs of the estate Product Owner page (TheHub #60884). Pure, so the
 * vitest suite runs it — the same reasoning as `lib/repo-tabs.ts`.
 *
 * Three nav entries — Product Owner, Review queue, Pull requests — were one
 * reader's three questions about the work across the estate: what each
 * repository has committed to, what is waiting on a person, and what is open
 * on GitHub. They are one page now, with the selection in `?tab=` like the
 * repository page, so a tab survives a refresh and can be sent to somebody.
 * The retired paths redirect here (`lib/retired-routes.ts`).
 */
export const PO_TABS = [
  { id: "estate", label: "Estate" },
  { id: "review", label: "Review queue" },
  { id: "pull-requests", label: "Pull requests" },
] as const;

export type PoTabId = (typeof PO_TABS)[number]["id"];

/** Is `tab` one of this page's tabs? Unknown ids are refused, not defaulted. */
export function isPoTab(tab: string): tab is PoTabId {
  return PO_TABS.some((entry) => entry.id === tab);
}

/**
 * The link to one tab. Estate is the landing tab, so it is the bare path, as
 * Dashboard is on the repository page; extra parameters (the selected pull
 * request) follow the tab.
 */
export function poTabHref(tab: PoTabId, extra: Record<string, string> = {}): string {
  const query = new URLSearchParams(tab === "estate" ? {} : { tab });
  for (const [key, value] of Object.entries(extra)) query.set(key, value);
  const rendered = query.toString();
  return rendered ? `/product-owner?${rendered}` : "/product-owner";
}
