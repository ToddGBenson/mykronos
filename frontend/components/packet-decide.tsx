"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { canRecord } from "@/lib/approval-packet";

/**
 * Decide a request from its packet (TheHub #61136, v2 P3).
 *
 * Any pending request, estate-wide ones included: it posts to the packet's
 * own route, which runs the verification check again, hands the decision to
 * the approvals engine and stores the check with it. The digest sent is the
 * one this page was rendered with, so a request whose evidence changed since
 * is refused rather than approved unseen.
 *
 * "Concur with the reviewer" chooses the reviewer's verdict and fills in a
 * rationale that says so in as many words; the person can still edit it. An
 * empty rationale cannot be recorded, and the engine refuses one anyway.
 * "Record" goes straight to the next pending request.
 */

const VERDICTS = [
  { id: "approve", label: "Approve" },
  { id: "reject", label: "Reject" },
  { id: "needs_info", label: "Needs info" },
] as const;

type Verdict = (typeof VERDICTS)[number]["id"];

export function PacketDecide({
  requestId,
  digest,
  concur,
  reviewerVerdict,
  nextHref,
  nextLabel,
}: {
  requestId: string;
  digest: string;
  /** The concur rationale, or null when concurring is not offered. */
  concur: string | null;
  reviewerVerdict: string | null;
  nextHref: string;
  nextLabel: string;
}) {
  const router = useRouter();
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [concurring, setConcurring] = useState(false);
  const [rationale, setRationale] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function toggleConcur(on: boolean) {
    setConcurring(on);
    if (on && concur) {
      setRationale(concur);
      if (VERDICTS.some((v) => v.id === reviewerVerdict)) setVerdict(reviewerVerdict as Verdict);
    } else if (!on && rationale === concur) {
      setRationale("");
    }
  }

  async function record() {
    if (!verdict || !canRecord(rationale)) return;
    setError(null);
    setBusy(true);
    try {
      const response = await fetch(
        `/api/product-owner/approvals/${encodeURIComponent(requestId)}/decision`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ verdict, rationale, evidence_digest: digest }),
        },
      );
      if (!response.ok) {
        const payload = (await response.json().catch(() => null)) as { detail?: unknown } | null;
        const detail = payload?.detail;
        setError(
          typeof detail === "string" && detail
            ? detail
            : `The decision was refused (HTTP ${response.status}).`,
        );
        return;
      }
      router.push(nextHref);
      router.refresh();
    } catch {
      setError("Could not reach this server.");
    } finally {
      setBusy(false);
    }
  }

  const ready = verdict !== null && canRecord(rationale) && !busy;
  return (
    <div className="flex flex-col gap-3 border-t border-rule-soft px-3 py-3">
      <div role="group" aria-label="Verdict" className="flex flex-wrap gap-2">
        {VERDICTS.map((option) => (
          <button
            key={option.id}
            type="button"
            aria-pressed={verdict === option.id}
            onClick={() => setVerdict(option.id)}
            className={`min-h-11 border px-4 text-[13px] font-semibold ${
              verdict === option.id
                ? "border-accent bg-accent text-paper"
                : "border-accent text-accent hover:bg-accent-wash"
            }`}
          >
            {option.label}
          </button>
        ))}
      </div>
      {concur ? (
        <label className="flex min-h-11 items-center gap-2 text-[13px] text-ink">
          <input
            type="checkbox"
            checked={concurring}
            onChange={(event) => toggleConcur(event.target.checked)}
            className="h-5 w-5 accent-[var(--color-accent)]"
          />
          Concur with the reviewer
          {reviewerVerdict ? (
            <span className="font-mono text-[12px] text-ink-3">({reviewerVerdict})</span>
          ) : null}
        </label>
      ) : null}
      <label className="flex flex-col gap-1 text-[12px] text-ink-2">
        Rationale: what you checked and saw. Recorded as your words, bound to digest{" "}
        <span className="font-mono text-[11px] text-ink-3">{digest.slice(0, 12)}</span>
        <textarea
          value={rationale}
          onChange={(event) => setRationale(event.target.value)}
          rows={4}
          maxLength={8000}
          className="border border-ink-3 bg-paper px-2 py-1.5 text-[13px] text-ink"
        />
      </label>
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          disabled={!ready}
          onClick={() => void record()}
          className="min-h-11 border border-accent bg-accent px-4 text-[13px] font-semibold text-paper disabled:border-ink-3 disabled:bg-paper-3 disabled:text-ink-2"
        >
          {`Record and ${nextLabel}`}
        </button>
        {!verdict ? (
          <span className="text-[12px] text-ink-3">Choose a verdict.</span>
        ) : !canRecord(rationale) ? (
          <span className="text-[12px] text-ink-3">A decision needs a rationale.</span>
        ) : null}
        {error ? (
          <span role="alert" className="max-w-prose text-[12px] text-critical">
            {error}
          </span>
        ) : null}
      </div>
    </div>
  );
}
