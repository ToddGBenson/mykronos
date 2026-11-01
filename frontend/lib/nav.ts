/**
 * The nav rail.
 *
 * It used to show unbuilt views disabled, labelled with the phase that would
 * deliver them — hiding them would have made the shipped slice look like the
 * whole design, and "where is the risk score?" deserved an answer rather than
 * a blank. As of Phase 7 there is nothing left to label, so the branch that
 * rendered those is gone rather than kept warm for a case that no longer
 * arises.
 *
 * Grouped by job since TheHub #61137 (P2, P5): fourteen items in one "Views"
 * group gave no sense of which were work and which were reading. Work is what
 * the operator acts on, Platform is how this product itself is set up and
 * running, and Reading is what they read.
 */
export const NAV: {
  section: string;
  items: { label: string; href: string }[];
}[] = [
  {
    section: "Work",
    items: [
      // First, because a pending decision is the one thing on this site that
      // blocks other people (P2). It was a tab under Product Owner, and the
      // only nav label that sounded like it, "Decisions", meant the scoring
      // policy. `/product-owner/review-queue` and `/product-owner?tab=review`
      // redirect here.
      { label: "Approvals", href: "/approvals" },
      { label: "Portfolio", href: "/" },
      { label: "Triage queue", href: "/triage" },
      // Beside the triage queue, not the portfolio: the queue is what to do
      // next, and this is the standing account of what is outstanding and
      // what was decided against — the two halves of the same job.
      {
        label: "Vulnerability management",
        href: "/vulnerability-management",
      },
      // The same backlog asked a different question: which of it is work
      // *today*. One entry for remediation, not two: the library is a
      // labelled section of this page (#library), the way #60820 folded the
      // repository page's Patchwork history into its Remediate today tab.
      // `/remediation` redirects here (`lib/retired-routes.ts`).
      { label: "Remediate today", href: "/remediate" },
      // The work rather than the code (spec 35 §8.7): every repository's
      // declared process and sprint, one row each, linking to its tab. The
      // open pull requests are its tab (TheHub #60884), and `/pull-requests`
      // redirects there.
      { label: "Product Owner", href: "/product-owner" },
    ],
  },
  {
    section: "Platform",
    items: [
      // The Oracle's scoring policy, what blocking mode would have cost, and
      // which terms move scores. Called "Decisions" until TheHub #61137,
      // which read as "approvals"; `/decisions` redirects here.
      { label: "Risk policy", href: "/risk-policy" },
      // The only item about this platform rather than the estate it watches.
      // A job that stopped here is invisible in exactly the way a stopped
      // scan lane is, and with the same consequence.
      //
      // Named for the product rather than "Platform health" (TheHub #60883):
      // the estate it watches has platforms of its own. The route keeps its
      // old name so bookmarks and runbooks still land.
      { label: "MyKronos Health", href: "/platform-health" },
    ],
  },
  {
    section: "Reading",
    items: [
      // What changed overnight, so what, and whether it is work (TheHub
      // #60864). The page the 07:00 Slack DM links to.
      { label: "Briefing", href: "/briefing" },
      // The Monday intelligence page per application (TheHub #60865), beside
      // the daily one: the same reader, the slower question.
      { label: "Weekly intelligence", href: "/briefing/weekly" },
      // Incident lookup lives here too: "what does the outside world think
      // matters" and "is it here" are two views of one question, and a KEV row
      // is exactly where the second one gets asked.
      { label: "Threat intelligence", href: "/threat-intel" },
      // Estate-wide by construction: how many distinct libraries are we
      // maintaining, and which are we carrying at several versions.
      { label: "Libraries", href: "/libraries" },
      { label: "Trends", href: "/trends" },
      { label: "Retros", href: "/retro" },
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
 * names.
 */
