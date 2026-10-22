import { permanentRedirect } from "next/navigation";

import { retiredRoute } from "@/lib/retired-routes";

/**
 * Retired: the review queue is a tab of the Product Owner page (TheHub #60884).
 * Permanent (308), as `/remediation` is: the move is. Each packet keeps its own
 * page below this path, so only the list moved.
 */
export default function ReviewQueuePage(): never {
  permanentRedirect(retiredRoute("/product-owner/review-queue"));
}
