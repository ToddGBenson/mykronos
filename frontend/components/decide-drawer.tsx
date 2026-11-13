import Link from "next/link";

import { PacketDecide } from "@/components/packet-decide";
import { Pill } from "@/components/primitives";
import { checkDetail, concurRationale, packetTime } from "@/lib/approval-packet";
import type { ReviewPacket } from "@/lib/po-console";
import { reviewerStanding } from "@/lib/review-queue";

/**
 * The Decide drawer on /today (TheHub #61142): one pending request's packet,
 * decided without leaving the run sheet. Rendered only when the run sheet's
 * actions are switched on.
 *
 * It is the 1b packet (`/product-owner/review-queue/[requestId]`, #61136),
 * shortened: the verification check's verdict, the digest, the reviewer's
 * standing and the same `PacketDecide`, which posts to the packet's own
 * decision route, binds the decision to this digest and runs the check again.
 * The full packet, with the evidence and the requester's claim, is one link
 * away, and nothing here decides anything the packet page could not.
 */

function verdictOf(holds: boolean | null): { tone: "pass" | "critical" | "muted"; word: string } {
  if (holds === true) return { tone: "pass", word: "check holds" };
  if (holds === false) return { tone: "critical", word: "check fails" };
  return { tone: "muted", word: "check incomplete" };
}

export function DecideDrawerView({
  packet,
  nextHref,
  nextLabel,
}: {
  packet: ReviewPacket;
  nextHref: string;
  nextLabel: string;
}) {
  const verification = packet.verification ?? null;
  const overall = verdictOf(verification?.holds ?? null);
  const standing = reviewerStanding(packet.reviewer);
  const concur =
    packet.superseded && packet.reviewer?.verdict === "approve"
      ? null
      : concurRationale(packet.reviewer, verification);
  return (
    <aside
      aria-labelledby="decide-drawer-title"
      className="flex flex-col gap-2 border border-accent bg-paper-2 px-3 py-2"
    >
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 id="decide-drawer-title" className="text-[15px] font-bold">
          {packet.duty} · {packet.tier}
        </h2>
        <span className="font-mono text-[12px] text-ink-3">
          {packet.subject_ref} · requested by {packet.requested_by} ({packet.requester_kind}) ·{" "}
          {packet.overdue ? "expired" : `expires ${packetTime(packet.expires_at) ?? "—"}`}
        </span>
        <Link
          href="/today"
          className="ml-auto text-[13px] text-accent underline-offset-2 hover:underline"
        >
          Close
        </Link>
      </div>
      {packet.superseded ? (
        <p role="status" className="border border-critical bg-critical-wash px-2 py-1 text-[13px]">
          Superseded: its pull request has left the head it names. Reject it.
        </p>
      ) : null}
      <p className="text-[13px] text-ink-2">{packet.summary}</p>
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        <Pill tone={overall.tone}>{overall.word}</Pill>
        <span className="text-ink-3">{checkDetail(verification)}</span>
        {packet.digest_verified ? (
          <Pill tone="pass">digest verified</Pill>
        ) : (
          <Pill tone="critical">digest mismatch</Pill>
        )}
        <Pill tone={standing.tone}>{standing.word}</Pill>
      </div>
      <Link
        href={`/product-owner/review-queue/${encodeURIComponent(packet.id)}`}
        className="self-start text-[13px] text-accent underline-offset-2 hover:underline"
      >
        Open the full packet: evidence and the requester&rsquo;s claim
      </Link>
      <PacketDecide
        requestId={packet.id}
        digest={packet.evidence_digest}
        concur={concur}
        reviewerVerdict={packet.reviewer?.verdict ?? null}
        nextHref={nextHref}
        nextLabel={nextLabel}
      />
    </aside>
  );
}
