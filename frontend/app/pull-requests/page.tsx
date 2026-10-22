import { permanentRedirect } from "next/navigation";

import { retiredRoute } from "@/lib/retired-routes";

/**
 * Retired: the pull requests list is a tab of the Product Owner page (TheHub
 * #60884). Permanent (308). A selected pull request (`?pr=`) is carried over,
 * so a link to one row still opens on that row.
 */
export default async function PullRequestsPage({
  searchParams,
}: {
  searchParams: Promise<{ pr?: string }>;
}): Promise<never> {
  const { pr } = await searchParams;
  const target = retiredRoute("/pull-requests");
  permanentRedirect(pr ? `${target}&pr=${encodeURIComponent(pr)}` : target);
}
