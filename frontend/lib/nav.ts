/**
 * The nav rail.
 *
 * It used to show unbuilt views disabled, labelled with the phase that would
 * deliver them — hiding them would have made the shipped slice look like the
 * whole design, and "where is the risk score?" deserved an answer rather than
 * a blank. As of Phase 7 there is nothing left to label, so the branch that
 * rendered those is gone rather than kept warm for a case that no longer
 * arises.
 */
export const NAV: {
  section: string;
  items: { label: string; href: string }[];
}[] = [
  {
    section: "Views",
    items: [
      { label: "Portfolio", href: "/" },
      { label: "Triage queue", href: "/triage" },
      // Incident lookup lives here too: "what does the outside world think
      // matters" and "is it here" are two views of one question, and a KEV row
      // is exactly where the second one gets asked.
      { label: "Threat intelligence", href: "/threat-intel" },
      // Beside threat intelligence, not under a repository: the question it
      // answers is estate-wide by construction — how many distinct libraries
      // are we maintaining, and which are we carrying at several versions.
      { label: "Libraries", href: "/libraries" },
      // Beside the triage queue, not the portfolio: the queue is what to do
      // next, and this is the standing account of what is outstanding and
      // what was decided against — the two halves of the same job.
      {
        label: "Vulnerability management",
        href: "/vulnerability-management",
      },
      // Directly after it, because it is the same backlog asked a different
      // question. Vulnerability management reports what is outstanding;
      // this answers which of it is work *today* — and on the day it was
      // written the honest split was 109 free, 316 frozen, 0 auto-fixable.
      //
      // One entry for remediation, not two. "Remediate today" and
      // "Remediation library" sat side by side and both answered "what do I
      // do about the fixes": the worklist, and the open Patchwork pull
      // requests that are part of that same work. The page now leads with
      // the worklist and carries the library as a labelled section below it
      // (#library), the way #60820 folded the repository page's Patchwork
      // history into its Remediate today tab. Same label as that tab, so the
      // estate view and the repository view are called the same thing.
      // `/remediation` redirects here (`lib/retired-routes.ts`).
      { label: "Remediate today", href: "/remediate" },
      { label: "Pull requests", href: "/pull-requests" },
      { label: "Decisions", href: "/decisions" },
      { label: "Trends", href: "/trends" },
      { label: "Retros", href: "/retro" },
      // The work rather than the code (spec 35 §8.7): every repository's
      // declared process and sprint, one row each, linking to its tab.
      { label: "Product Owner", href: "/product-owner" },
      // The operator's own question across that estate (D-163): which
      // decisions are waiting on a person, and which approved PRs can merge.
      { label: "Review queue", href: "/product-owner/review-queue" },
      // Last, and the only item about this platform rather than the estate it
      // watches. It reports on four repositories and had no page reporting on
      // itself; a job that stopped here is invisible in exactly the way a
      // stopped scan lane is, and with the same consequence.
      //
      // Named for the product rather than "Platform health" (TheHub #60883):
      // the estate it watches has platforms of its own, and the label should
      // say whose health this is. The route keeps its old name so bookmarks
      // and runbooks still land.
      { label: "MyKronos Health", href: "/platform-health" },
    ],
  },
];

/**
 * The "Manage" section is gone, and its absence is the fix.
 *
 * It held three items and no destinations of its own: "Repositories" pointed
 * at `/` (Portfolio), "Knowledge" pointed at `/retro` (Retros), and "Risk
 * decision policy" pointed at an anchor inside Decisions. Thirteen labels led
 * to ten places.
 *
 * A sidebar is a map. When two labels lead to one location the map is wrong,
 * the active-state highlight cannot be correct for both, and a reader building
 * a model of the product quietly gets a worse one. Deleting the aliases is
 * honest; the pages they pointed at all remain reachable under their real
 * names, one line above.
 */
