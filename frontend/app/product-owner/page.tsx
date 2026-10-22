import Link from "next/link";

import { PoEstateTab } from "@/components/po-estate";
import { PullRequestsTab } from "@/components/po-pull-requests";
import { ReviewQueueTab } from "@/components/po-review-queue";
import { ErrorPanel } from "@/components/primitives";
import { PO_TABS, isPoTab, poTabHref } from "@/lib/po-tabs";

export const dynamic = "force-dynamic";

/**
 * The Product Owner page (TheHub #60884): the estate roll-up, the review queue
 * and the open pull requests, as three tabs of one page rather than three nav
 * entries. Each tab is the page it replaced, unchanged; `/product-owner/review-queue`
 * and `/pull-requests` redirect to their tab.
 *
 * The per-repository Product Owner tab is a different page and is untouched.
 */
export default async function ProductOwnerPage({
  searchParams,
}: {
  searchParams: Promise<{ tab?: string; pr?: string }>;
}) {
  const { tab = "estate", pr } = await searchParams;

  // As on the repository page (B-006): a wrong link that rendered Estate would
  // look like a working one.
  if (!isPoTab(tab)) {
    return (
      <ErrorPanel
        title="No such tab"
        detail={`'${tab}' is not a tab on this page. Valid ids: ${PO_TABS.map(
          (entry) => entry.id,
        ).join(", ")}.`}
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-bold tracking-tight">Product Owner</h1>
      <nav className="flex flex-wrap border-b-2 border-ink-2" aria-label="Product Owner views">
        {PO_TABS.map((entry) => (
          <Link
            key={entry.id}
            href={poTabHref(entry.id)}
            aria-current={tab === entry.id ? "page" : undefined}
            className={`-mb-0.5 border-b-2 px-3 py-1.5 font-mono text-[12px] ${
              tab === entry.id
                ? "border-accent font-bold text-ink"
                : "border-transparent text-ink-3 hover:text-accent"
            }`}
          >
            {entry.label}
          </Link>
        ))}
      </nav>
      {tab === "review" ? (
        <ReviewQueueTab />
      ) : tab === "pull-requests" ? (
        <PullRequestsTab selectedNumber={pr} />
      ) : (
        <PoEstateTab />
      )}
    </div>
  );
}
