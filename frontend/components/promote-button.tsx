"use client";

/**
 * Approving a promotion candidate (spec 19 §2.3).
 *
 * `promotion.py` has always found candidates and said "a person decides" —
 * the deciding was the half never built, so a candidate could be read and not
 * acted on. This is the click.
 *
 * Deliberately not a confirmation dialog: promotion adds an entry at the
 * wider tier and leaves the evidence in place, so it is reversible by the
 * same admin who did it and audited either way. A modal here would imply a
 * finality the action does not have.
 */

import { useState } from "react";

import type { paths } from "@/lib/api-types";

type PromotionResult =
  paths["/api/knowledge/promotion-candidates/{subject}/approve"]["post"]["responses"]["200"]["content"]["application/json"];

export function PromoteButton({
  subject,
  sourceType,
  toTier,
}: {
  subject: string;
  sourceType: string;
  toTier: string;
}) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PromotionResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function approve() {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/knowledge/promotion-candidates/${encodeURIComponent(subject)}/approve`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ source_type: sourceType }),
        },
      );
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        setError(
          typeof body?.detail === "string"
            ? body.detail
            : `The request was refused (HTTP ${response.status}).`,
        );
        return;
      }
      setResult(body as PromotionResult);
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    return (
      <p className="max-w-prose font-mono text-[12px] text-pass">
        Promoted to {result.to_tier}. {result.note}
        {result.reasons_withheld > 0 ? (
          <span className="text-ink-3">
            {" "}
            {result.reasons_withheld} restricted reason
            {result.reasons_withheld === 1 ? "" : "s"} stayed behind.
          </span>
        ) : null}
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-1">
      <button
        type="button"
        onClick={approve}
        disabled={busy}
        className={`self-start border border-accent px-1.5 py-0.5 font-mono text-[11px] text-accent ${
          busy ? "opacity-40" : "hover:bg-accent hover:text-paper"
        }`}
      >
        {busy ? "promoting…" : `promote to ${toTier}`}
      </button>
      {error ? <p className="font-mono text-[11px] text-critical">{error}</p> : null}
    </div>
  );
}
