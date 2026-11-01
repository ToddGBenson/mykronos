import { getReviewQueue } from "@/lib/po-console";

/**
 * The ids of the pending requests, in the queue's order (soonest to expire
 * first), for the packet's "Record and next" (TheHub #61136). Superseded
 * requests are not in it. Empty when the queue cannot be read, which sends
 * "next" back to Approvals rather than failing the packet.
 */
export async function pendingRequestIds(): Promise<string[]> {
  const queue = await getReviewQueue();
  return queue.ok ? queue.data.pending.map((item) => item.id) : [];
}
