/**
 * Top-level routes that have been retired, and where their links now land.
 * Pure, so the vitest suite runs it — the same reasoning as `RETIRED_TABS` in
 * `lib/repo-tabs.ts`: a retired path still arrives in bookmarks, Slack threads
 * and specs written while it existed, so it has to be mapped, not deleted.
 */
export const RETIRED_ROUTES: Readonly<Record<string, string>> = {
  // "Remediation library" was a second nav entry beside "Remediate today".
  // Its content — open Patchwork PRs grouped by fix, and fix efficacy — is now
  // the #library section of Remediate today.
  "/remediation": "/remediate#library",
};

/** Where a retired path now lands. Throws for a path that was never retired. */
export function retiredRoute(path: string): string {
  if (!Object.hasOwn(RETIRED_ROUTES, path)) {
    throw new Error(`${path} is not a retired route`);
  }
  return RETIRED_ROUTES[path];
}
