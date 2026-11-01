"use client";

/**
 * Revoking an agent credential (TheHub #61144).
 *
 * Two clicks, unlike `promote-button.tsx`: a revocation cannot be undone and
 * it takes every live sub-agent with it, so the second click names how many.
 * The agent loses the platform mid-run; re-minting gives it a new identity,
 * not the old one back.
 */

import { useRouter } from "next/navigation";
import { useState } from "react";

export function RevokeCredential({
  instance,
  descendants,
}: {
  instance: string;
  descendants: number;
}) {
  const router = useRouter();
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function revoke() {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/agents/credentials/${encodeURIComponent(instance)}/revoke`,
        { method: "POST" },
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
      setArmed(false);
      router.refresh();
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  const button =
    "min-h-11 border px-3 font-mono text-[12px] font-bold uppercase tracking-[0.08em] disabled:opacity-50";

  return (
    <span className="flex flex-wrap items-center gap-2">
      {armed ? (
        <>
          <button
            type="button"
            onClick={revoke}
            disabled={busy}
            className={`${button} border-critical bg-critical-wash text-critical`}
          >
            {busy
              ? "Revoking…"
              : descendants > 0
                ? `Revoke it and ${descendants} sub-agent${descendants === 1 ? "" : "s"}`
                : "Revoke it"}
          </button>
          <button
            type="button"
            onClick={() => setArmed(false)}
            disabled={busy}
            className={`${button} border-rule text-ink-2`}
          >
            Keep
          </button>
        </>
      ) : (
        <button
          type="button"
          onClick={() => setArmed(true)}
          className={`${button} border-rule text-ink-2 hover:border-critical hover:text-critical`}
          aria-label={`Revoke ${instance}`}
        >
          Revoke
        </button>
      )}
      {error ? (
        <span role="alert" className="font-mono text-[12px] text-critical">
          {error}
        </span>
      ) : null}
    </span>
  );
}
