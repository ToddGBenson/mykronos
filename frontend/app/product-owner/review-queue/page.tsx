import Link from "next/link";

import { EmptyState, ErrorPanel, Pill, Section, StatTile } from "@/components/primitives";
import { getReviewQueue, type MergeRow, type ReviewQueueItem } from "@/lib/po-console";
import { mergeReadiness, reviewerStanding } from "@/lib/review-queue";

export const dynamic = "force-dynamic";

/**
 * The operator's review queue (D-163): what is waiting on a person, estate-wide.
 *
 * Read-only. Each pending request shows the platform's summary of its frozen
 * evidence, the requester's claim labelled as a claim, and the platform
 * reviewer's verdict as advice; its packet holds the rest. Deciding goes
 * through the approvals engine, in place on the repository's tab or from the
 * packet, never from this list.
 */

function day(value: string | null | undefined): string {
  return value ? value.slice(0, 16).replace("T", " ") : "—";
}

function PendingRow({ item }: { item: ReviewQueueItem }) {
  const standing = reviewerStanding(item.reviewer);
  return (
    <div className="flex flex-col gap-1 border-b border-rule-soft px-3 py-2 text-[12px] text-ink-2">
      <div className="flex flex-wrap items-baseline gap-2">
        <Link
          href={`/product-owner/review-queue/${encodeURIComponent(item.id)}`}
          className="font-mono text-ink hover:text-accent"
        >
          {item.duty} · {item.tier}
        </Link>
        <span className="text-ink">{item.summary || item.subject_ref}</span>
        <span className="ml-auto font-mono text-[11px] text-ink-3">
          {item.overdue ? <Pill tone="critical">expired</Pill> : `expires ${day(item.expires_at)}`}
        </span>
      </div>
      <span className="font-mono text-[11px] text-ink-3">
        {item.repo_full_name ?? "estate-wide"} · requested by {item.requested_by} (
        {item.requester_kind}) · digest {item.evidence_digest.slice(0, 12)}
      </span>
      {item.requester_claim ? (
        <span>
          <span className="font-mono text-[11px] text-ink-3">requester&rsquo;s claim, not evidence:</span>{" "}
          {item.requester_claim.length > 280
            ? `${item.requester_claim.slice(0, 280)}…`
            : item.requester_claim}
        </span>
      ) : null}
      <span className="flex flex-wrap items-baseline gap-2">
        <span className="font-mono text-[11px] text-ink-3">platform reviewer:</span>
        <Pill tone={standing.tone}>{standing.word}</Pill>
        {item.decisions.length ? (
          <span className="font-mono text-[11px] text-ink-3">
            {item.decisions.length} decision(s) recorded
          </span>
        ) : null}
        <Link
          href={`/product-owner/review-queue/${encodeURIComponent(item.id)}`}
          className="ml-auto font-mono text-[11px] text-accent hover:underline"
        >
          open the packet
        </Link>
      </span>
    </div>
  );
}

function MergeLine({ row }: { row: MergeRow }) {
  const label = mergeReadiness(row);
  const pr = row.number ? `#${row.number}` : "PR";
  return (
    <div className="flex flex-wrap items-baseline gap-2 border-b border-rule-soft px-3 py-1.5 text-[12px]">
      <Pill tone={label.tone} title={row.github_error ?? undefined}>
        {label.word}
      </Pill>
      {row.number ? (
        <a
          href={`https://github.com/${row.repo_full_name}/pull/${row.number}`}
          className="font-mono text-ink hover:text-accent"
        >
          {row.repo_full_name}
          {pr}
        </a>
      ) : (
        <span className="font-mono">{row.repo_full_name}</span>
      )}
      <span className="text-ink-2">{row.title}</span>
      <span className="ml-auto font-mono text-[11px] text-ink-3">
        approved at {row.approved_head_sha.slice(0, 8)} by {row.approvers.join(", ") || "—"}
      </span>
    </div>
  );
}

export default async function ReviewQueuePage() {
  const result = await getReviewQueue();
  if (!result.ok) {
    return <ErrorPanel title="Review queue unavailable" detail={result.error} />;
  }
  const { counts, pending, ready_to_merge: merges, reviewer } = result.data;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-bold tracking-tight">Review queue</h1>
        <p className="max-w-prose text-[12px] text-ink-2">
          What is waiting on a person, across every repository. The summary is the
          platform&rsquo;s own evidence; the claim is the requester&rsquo;s and is labelled as
          one; the platform reviewer&rsquo;s verdict is advice. Open a packet to see all three
          side by side and decide. An agent never approves its own work: the approvals engine
          refuses it whatever this page shows.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <StatTile label="Pending decisions" value={counts.pending} sub="oldest expiry first" />
        <StatTile
          label="Not reviewed"
          value={counts.unreviewed}
          sub={`reviewer mode: ${reviewer.mode}`}
        />
        <StatTile
          label="Expired, not decided"
          value={counts.overdue}
          alert={counts.overdue > 0}
          sub="the engine will refuse these"
        />
        <StatTile label="Ready to merge" value={counts.ready_to_merge} sub="approved, head unchanged" />
      </div>
      <Section
        title="Pending decisions"
        detail={
          reviewer.agreement === null
            ? "reviewer agreement: no decided history yet"
            : `reviewer agreed with people on ${Math.round(reviewer.agreement * 100)}% of delegable decisions`
        }
      >
        {pending.length === 0 ? (
          <EmptyState title="Nothing waiting" detail="No approval request is pending." />
        ) : (
          pending.map((item) => <PendingRow key={item.id} item={item} />)
        )}
      </Section>
      <Section title="Approved pull requests" detail="still open on GitHub">
        {merges.length === 0 ? (
          <p className="px-3 py-2 text-[12px] text-ink-3">
            No approved pull request is still open.
          </p>
        ) : (
          merges.map((row) => <MergeLine key={row.request_id} row={row} />)
        )}
      </Section>
    </div>
  );
}
