import { DecideApproval } from "@/components/po-approval-decide";
import { Crumb, ErrorPanel, Pill, Section } from "@/components/primitives";
import { getReviewPacket } from "@/lib/po-console";
import { poTabHref } from "@/lib/po-tabs";
import { reviewerStanding } from "@/lib/review-queue";

export const dynamic = "force-dynamic";

/**
 * One request's review packet (D-163): the requester's claim, the platform's
 * frozen evidence and the platform reviewer's verdict, kept apart, then the
 * decision.
 *
 * The decision control is the repository tab's own (D-144): it posts the
 * digest this page was rendered with, and the approvals engine applies every
 * rule for the tier. A request that names no onboarded repository is decided
 * through the approvals API instead, and the page says so.
 */

type Check = { claim?: unknown; holds?: unknown; note?: unknown };

export default async function ReviewPacketPage({
  params,
}: {
  params: Promise<{ requestId: string }>;
}) {
  const { requestId } = await params;
  const result = await getReviewPacket(requestId);
  if (!result.ok) {
    return <ErrorPanel title="Review packet unavailable" detail={result.error} />;
  }
  const packet = result.data;
  const standing = reviewerStanding(packet.reviewer);
  const checks = (packet.reviewer?.checks ?? []) as Check[];
  return (
    <div className="flex flex-col gap-4">
      <Crumb href={poTabHref("review")}>Review queue</Crumb>
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-bold tracking-tight">
          {packet.duty} · {packet.tier}
        </h1>
        <p className="font-mono text-[12px] text-ink-3">
          {packet.subject_ref} · {packet.repo_full_name ?? "estate-wide"} · requested by{" "}
          {packet.requested_by} ({packet.requester_kind}) ·{" "}
          {packet.overdue ? "expired" : `expires ${packet.expires_at?.slice(0, 16) ?? "—"}`}
        </p>
      </div>

      <Section title="1 · The requester's claim" detail="a claim to test, not evidence">
        <p className="whitespace-pre-wrap px-3 py-2 text-[13px] text-ink-2">
          {packet.requester_claim || "(no statement given)"}
        </p>
      </Section>

      <Section
        title="2 · The frozen evidence"
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
        <pre className="max-h-[32rem] overflow-auto border-t border-rule-soft px-3 py-2 font-mono text-[11px] text-ink-2">
          {JSON.stringify(packet.evidence, null, 2)}
        </pre>
      </Section>

      <Section
        title="3 · The platform reviewer"
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

      <Section title="4 · Decisions" detail={`${packet.decisions.length} recorded`}>
        {packet.decisions.map((decision, index) => (
          <p key={index} className="px-3 py-1.5 text-[12px] text-ink-2">
            <Pill tone={decision.verdict === "approve" ? "pass" : "warn"}>{decision.verdict}</Pill>{" "}
            <span className="font-mono">{decision.approver}</span> ({decision.approver_kind}):{" "}
            {decision.rationale}
          </p>
        ))}
        {packet.needs ? (
          <p className="px-3 py-1.5 font-mono text-[11px] text-ink-3">
            this tier needs: {JSON.stringify(packet.needs)}
          </p>
        ) : null}
        {packet.repo_id ? (
          <>
            <p className="px-3 pt-2 text-[12px] text-ink-2">
              Your rationale is recorded as your own words, against the digest above. If you
              agree with the reviewer, say what you checked and that you concur.
            </p>
            <DecideApproval
              repoId={packet.repo_id}
              requestId={packet.id}
              digest={packet.evidence_digest}
            />
          </>
        ) : (
          <p className="border-t border-rule-soft px-3 py-1.5 text-[12px] text-ink-3">
            This request names no onboarded repository, so it is decided through{" "}
            <span className="font-mono">POST /api/approvals/{packet.id}/decisions</span>, not
            here.
          </p>
        )}
      </Section>
    </div>
  );
}
