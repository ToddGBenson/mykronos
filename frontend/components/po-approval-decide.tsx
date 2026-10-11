"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

/**
 * Decide one approval request in place (spec 35 §8.2, D-137).
 *
 * The digest sent is the one this row was rendered with, so a request whose
 * evidence changed after the page loaded is refused by the engine rather than
 * approved unseen. A refusal is shown exactly as the engine wrote it: it names
 * the spec 34 rule the decision did not meet.
 */

const VERDICTS = [
  { id: "approve", label: "approve" },
  { id: "reject", label: "reject" },
  { id: "needs_info", label: "needs info" },
] as const;

export function DecideApproval({
  repoId,
  requestId,
  digest,
}: {
  repoId: string;
  requestId: string;
  digest: string;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState(false);
  const [rationale, setRationale] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(verdict: string) {
    setError(null);
    setBusy(true);
    try {
      const response = await fetch(
        `/api/repos/${encodeURIComponent(repoId)}/product-owner/approvals/${encodeURIComponent(
          requestId,
        )}/decision`,
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
      setRationale("");
      startTransition(() => router.refresh());
    } catch {
      setError("Could not reach this server.");
    } finally {
      setBusy(false);
    }
  }

  const disabled = pending || busy || rationale.trim().length === 0;
  return (
    <div className="flex flex-col gap-1.5 border-t border-rule-soft px-3 py-2">
      <label className="flex flex-col gap-1 text-[12px] text-ink-2">
        Rationale (recorded as the reason, against digest{" "}
        <span className="font-mono text-[11px] text-ink-3">{digest.slice(0, 12)}</span>)
        <textarea
          value={rationale}
          onChange={(event) => setRationale(event.target.value)}
          rows={2}
          maxLength={8000}
          className="border border-rule bg-paper px-2 py-1 font-mono text-[12px] text-ink"
        />
      </label>
      <div className="flex flex-wrap items-baseline gap-2">
        {VERDICTS.map((verdict) => (
          <button
            key={verdict.id}
            type="button"
            disabled={disabled}
            onClick={() => void submit(verdict.id)}
            className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40"
          >
            {verdict.label}
          </button>
        ))}
        {error ? (
          <span role="alert" className="max-w-prose text-[12px] text-critical">
            {error}
          </span>
        ) : null}
      </div>
    </div>
  );
}
