"use client";

/**
 * Overriding a risk decision (spec 21 §4).
 *
 * `POST /decisions/{id}/override` has worked since spec 09 — audited,
 * one-shot, reason mandatory — and had no way to reach it that did not
 * involve knowing the URL. Nothing about the contract changes here.
 *
 * The reason field is required by the *server*, not just by this form, and
 * spec 09 §6 explains why: an override is the single most valuable signal for
 * tuning the policy, and an override with no reason throws that away. The
 * form says so rather than presenting an unexplained mandatory field.
 *
 * Collapsed behind a small link rather than shown open. Overriding is a
 * deliberate act, and a form sitting permanently under every decision reads
 * as an invitation to dismiss the score.
 */

import { useState } from "react";

import { RelativeTime } from "@/components/primitives";

const ACCEPTED = [
  { value: "go", label: "go" },
  { value: "review_recommended", label: "review recommended" },
  { value: "no_go", label: "no go" },
] as const;

type Recorded = {
  reason: string;
  overridden_by: string;
  original_recommendation: string;
  accepted_recommendation: string;
  overridden_at: string;
};

export function OverrideDecision({
  decisionId,
  recommendation,
}: {
  decisionId: string;
  recommendation: string;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState("");
  const [accepted, setAccepted] = useState("go");
  const [error, setError] = useState<string | null>(null);
  const [recorded, setRecorded] = useState<Recorded | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!reason.trim()) {
      setError("A reason is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/oracle/decisions/${encodeURIComponent(decisionId)}/override`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            reason: reason.trim(),
            accepted_recommendation: accepted,
          }),
        },
      );
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        // Passed through verbatim: 409 "already overridden" and 404 "no such
        // decision" tell a person two different things to do next.
        setError(
          typeof body?.detail === "string"
            ? body.detail
            : `The override was refused (HTTP ${response.status}).`,
        );
        return;
      }
      setRecorded({
        reason: reason.trim(),
        overridden_by: body?.overridden_by ?? "you",
        original_recommendation: recommendation,
        accepted_recommendation: accepted,
        overridden_at: body?.overridden_at ?? new Date().toISOString(),
      });
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  // Rendered in the same shape the server-rendered override block uses, so
  // the page does not visibly change character between "just overridden" and
  // "overridden, then reloaded".
  if (recorded) {
    return (
      <div className="border-t border-rule-soft bg-accent-wash px-3 py-2">
        <p className="max-w-prose text-[11px] leading-relaxed text-ink-2">
          {recorded.reason}
        </p>
        <p className="mt-1 font-mono text-[10px] text-ink-3">
          {recorded.overridden_by} · {recorded.original_recommendation} →{" "}
          {recorded.accepted_recommendation} ·{" "}
          <RelativeTime value={recorded.overridden_at} />
        </p>
      </div>
    );
  }

  if (!open) {
    return (
      <div className="border-t border-rule-soft px-3 py-1.5">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="font-mono text-[9px] text-ink-3 underline decoration-dotted hover:text-accent"
        >
          override this decision
        </button>
      </div>
    );
  }

  return (
    <form
      onSubmit={submit}
      className="flex flex-col gap-2 border-t border-rule-soft bg-paper px-3 py-2"
    >
      <label className="flex flex-wrap items-center gap-2 font-mono text-[10px] text-ink-3">
        accept instead
        <select
          value={accepted}
          onChange={(event) => setAccepted(event.target.value)}
          className="border border-rule bg-paper-2 px-1 py-0.5 font-mono text-[10px] text-ink"
        >
          {ACCEPTED.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <span className="text-ink-3">
          instead of {recommendation.replace(/_/g, " ")}
        </span>
      </label>

      <label className="flex flex-col gap-1">
        <span className="font-mono text-[10px] text-ink-3">
          why — recorded permanently, and read when the policy is tuned
        </span>
        <textarea
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          rows={2}
          maxLength={2000}
          required
          className="w-full max-w-prose border border-rule bg-paper-2 px-1.5 py-1 text-[11px] text-ink"
        />
      </label>

      <p className="max-w-prose text-[10px] leading-relaxed text-ink-3">
        The decision itself is not rewritten. This is recorded alongside it, so
        the history shows both what Oracle said and what you did about it — and
        it can only be done once.
      </p>

      <div className="flex items-center gap-2">
        <button
          type="submit"
          disabled={busy || !reason.trim()}
          className={`border border-accent px-1.5 py-0.5 font-mono text-[9px] text-accent ${
            busy || !reason.trim() ? "opacity-40" : "hover:bg-accent hover:text-paper"
          }`}
        >
          {busy ? "recording…" : "record override"}
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="font-mono text-[9px] text-ink-3 hover:text-ink"
        >
          cancel
        </button>
      </div>

      {error ? <p className="font-mono text-[9px] text-critical">{error}</p> : null}
    </form>
  );
}
