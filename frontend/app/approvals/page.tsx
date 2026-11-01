import { ReviewQueueTab } from "@/components/po-review-queue";

export const dynamic = "force-dynamic";

/**
 * Approvals (TheHub #61137, P2): everything waiting on a person, across every
 * repository, first in the nav rail.
 *
 * It was the Review queue tab of Product Owner, two levels down, under a
 * heading that did not say "approval" anywhere. The list is unchanged; only
 * where it lives and what it is called moved. `/product-owner/review-queue`
 * and `/product-owner?tab=review` redirect here, and each packet keeps its
 * own page under `/product-owner/review-queue/<id>`.
 */
export default async function ApprovalsPage() {
  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-bold tracking-tight">Approvals</h1>
      <ReviewQueueTab />
    </div>
  );
}
