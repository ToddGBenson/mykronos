import { PacketDecide } from "@/components/packet-decide";
import { Crumb, ErrorPanel, Pill, Section } from "@/components/primitives";
import { getReviewPacket } from "@/lib/po-console";
import { reviewerStanding } from "@/lib/review-queue";

import {
  checkDetail,
  concurRationale,
  evidenceFields,
  nextLabel,
  nextRequestHref,
  packetTime,
  tierNeeds,
} from "@/lib/approval-packet";
import { pendingRequestIds } from "@/lib/approval-queue";

export const dynamic = "force-dynamic";

/**
 * One request's review packet (D-163): the requester's claim, the platform's
 * frozen evidence and the platform reviewer's verdict, kept apart, then the
 * decision.
 *
 * Since TheHub #61136 it is Review-PendingApprovals.ps1's packet: the
 * platform's verification check runs when the page opens and its output is
 * shown; the evidence is fields, with the JSON one click away; concurring
 * with the reviewer fills in a rationale that says so; any request can be
 * decided here, estate-wide ones included; and "Record" goes straight to the
 * next pending request. The decision is bound to the digest this page was
 * rendered with, and the platform stores the check, re-run, with it.
 */

type Check = { claim?: unknown; holds?: unknown; note?: unknown };

function verdictOf(holds: boolean | null): { tone: "pass" | "critical" | "muted"; word: string } {
  if (holds === true) return { tone: "pass", word: "check holds" };
  if (holds === false) return { tone: "critical", word: "check fails" };
  return { tone: "muted", word: "check incomplete" };
}

function lineWord(ok: boolean | null): { tone: "pass" | "critical" | "muted"; word: string } {
  if (ok === true) return { tone: "pass", word: "holds" };
  if (ok === false) return { tone: "critical", word: "fails" };
  return { tone: "muted", word: "unknown" };
}

export default async function ReviewPacketPage({
  params,
}: {
  params: Promise<{ requestId: string }>;
}) {
  const { requestId } = await params;
  const [result, pendingIds] = await Promise.all([
    getReviewPacket(requestId),
    pendingRequestIds(),
  ]);
  if (!result.ok) {
    return <ErrorPanel title="Review packet unavailable" detail={result.error} />;
  }
  const packet = result.data;
  const standing = reviewerStanding(packet.reviewer);
  const checks = (packet.reviewer?.checks ?? []) as Check[];
  const verification = packet.verification ?? null;
  const overall = verdictOf(verification?.holds ?? null);
  const concur =
    packet.superseded && packet.reviewer?.verdict === "approve"
      ? null
      : concurRationale(packet.reviewer, verification);
  const fields = evidenceFields(packet.evidence);
  return (
    <div className="flex flex-col gap-4">
      <Crumb href="/approvals">Approvals</Crumb>
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-bold tracking-tight">
          {packet.duty} · {packet.tier}
        </h1>
        <p className="font-mono text-[12px] text-ink-3">
          {packet.subject_ref} · {packet.repo_full_name ?? "estate-wide"} · requested by{" "}
          {packet.requested_by} ({packet.requester_kind}) ·{" "}
          {packet.overdue ? "expired" : `expires ${packetTime(packet.expires_at) ?? "—"}`}
        </p>
      </div>

      {packet.superseded ? (
        <p
          role="status"
          className="border border-critical bg-critical-wash px-3 py-2 text-[13px] text-ink"
        >
          This request is superseded: its pull request has left the head it names, so approving
          it covers nothing. Reject it, with &ldquo;superseded by a newer head&rdquo; as the
          rationale.
        </p>
      ) : null}

      <Section
        title="1 · Verification check"
        detail={checkDetail(verification)}
        aside={<Pill tone={overall.tone}>{overall.word}</Pill>}
      >
        {verification ? (
          <ul className="flex flex-col gap-1.5 px-3 py-2 text-[13px] text-ink">
            {verification.lines.map((line, index) => {
              const word = lineWord(line.ok ?? null);
              return (
                <li key={index} className="flex flex-wrap items-baseline gap-2">
                  <Pill tone={word.tone}>{word.word}</Pill>
                  <span className="font-mono text-[12px]">{line.text}</span>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="px-3 py-2 text-[12px] text-ink-3">The platform did not run a check.</p>
        )}
        <p className="border-t border-rule-soft px-3 py-1.5 text-[12px] text-ink-3">
          Reload the page to run it again. It runs once more when you record your decision, and
          that output is stored with it.
        </p>
      </Section>

      <Section title="2 · The requester's claim" detail="a claim to test, not evidence">
        <p className="whitespace-pre-wrap px-3 py-2 text-[13px] text-ink-2">
          {packet.requester_claim || "(no statement given)"}
        </p>
      </Section>

      <Section
        title="3 · The frozen evidence"
        detail={`digest ${packet.evidence_digest.slice(0, 16)}`}
        aside={
          packet.digest_verified ? (
            <Pill tone="pass" title="The stored evidence hashes to the digest decisions bind to.">
              digest verified
            </Pill>
          ) : (
            <Pill
              tone="critical"
              title="The stored evidence no longer hashes to its digest. Do not decide on it."
            >
              digest mismatch
            </Pill>
          )
        }
      >
        <p className="px-3 pt-2 text-[12px] text-ink-2">{packet.summary}</p>
        {packet.review_instructions ? (
          <div className="px-3 py-2 text-[12px] text-ink-2">
            <span className="font-mono text-[11px] text-ink-3">
              what the policy asks an approver to check:
            </span>
            <p className="mt-1 whitespace-pre-wrap">{packet.review_instructions}</p>
          </div>
        ) : null}
        <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1 px-3 py-2 text-[12px]">
          {fields.map((field) => (
            <div key={field.key} className="contents">
              <dt className="font-mono text-ink-3">{field.label}</dt>
              <dd className="m-0 break-words font-mono text-ink">{field.value}</dd>
            </div>
          ))}
        </dl>
        <details className="border-t border-rule-soft px-3 py-2">
          <summary className="cursor-pointer text-[12px] text-accent">
            Show the raw evidence (JSON)
          </summary>
          <pre className="mt-2 max-h-[32rem] overflow-auto font-mono text-[11px] text-ink-2">
            {JSON.stringify(packet.evidence, null, 2)}
          </pre>
        </details>
      </Section>

      <Section
        title="4 · The platform reviewer"
        detail={packet.reviewer?.model ?? undefined}
        aside={<Pill tone={standing.tone}>{standing.word}</Pill>}
      >
        {packet.reviewer ? (
          <div className="flex flex-col gap-1 px-3 py-2 text-[12px] text-ink-2">
            <p className="whitespace-pre-wrap">{packet.reviewer.rationale}</p>
            {checks.map((check, index) => (
              <span key={index}>
                <Pill tone={check.holds ? "pass" : "critical"}>
                  {check.holds ? "holds" : "fails"}
                </Pill>{" "}
                {String(check.claim ?? "")}: {String(check.note ?? "")}
              </span>
            ))}
          </div>
        ) : (
          <p className="px-3 py-2 text-[12px] text-ink-3">
            The platform reviewer has not reviewed this request.
          </p>
        )}
      </Section>

      <Section title="5 · Decide" detail={`${packet.decisions.length} recorded so far`}>
        {packet.decisions.map((decision, index) => (
          <p key={index} className="px-3 py-1.5 text-[12px] text-ink-2">
            <Pill tone={decision.verdict === "approve" ? "pass" : "warn"}>{decision.verdict}</Pill>{" "}
            <span className="font-mono">{decision.approver}</span> ({decision.approver_kind}):{" "}
            {decision.rationale}
          </p>
        ))}
        {packet.needs ? (
          <p className="px-3 py-1.5 text-[12px] text-ink-2">
            {tierNeeds(packet.needs)}
          </p>
        ) : null}
        <PacketDecide
          requestId={packet.id}
          digest={packet.evidence_digest}
          concur={concur}
          reviewerVerdict={packet.reviewer?.verdict ?? null}
          nextHref={nextRequestHref(pendingIds, packet.id)}
          nextLabel={nextLabel(pendingIds, packet.id)}
        />
      </Section>
    </div>
  );
}
