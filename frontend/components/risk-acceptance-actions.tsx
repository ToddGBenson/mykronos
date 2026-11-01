"use client";

/**
 * Renew, revoke, or record the interim review of a risk acceptance (TheHub
 * #61140, spec 33).
 *
 * Offered only for the actions the backend's `actions_for` lists for this
 * record's status, so a button here is one the route would not refuse for
 * status. Each requires words: a renewal says why it should run longer, a
 * revocation says why it ends (its findings re-open), and an interim review
 * says what was checked.
 */

import { useRouter } from "next/navigation";
import { useState } from "react";

import { acceptanceActionProblem, type AcceptanceAction } from "@/lib/finding-decision";

const COPY: Record<AcceptanceAction, { button: string; field: string; placeholder: string }> = {
  "interim-review": {
    button: "Record the interim review",
    field: "What you checked",
    placeholder: "e.g. still not exposed: the port is unpublished and the image unchanged",
  },
  renew: {
    button: "Propose the renewal",
    field: "Why it should run longer",
    placeholder: "e.g. the vendor fix is scheduled for next month",
  },
  revoke: {
    button: "Revoke it",
    field: "Why it ends",
    placeholder: "e.g. a fix shipped; remediate instead",
  },
};

export function RiskAcceptanceActions({
  recordId,
  actions,
}: {
  recordId: string;
  /** The `path`s from the record's `actions`, e.g. `/api/risk-acceptances/x/renew`. */
  actions: string[];
}) {
  const offered = (["interim-review", "renew", "revoke"] as const).filter((a) =>
    actions.some((path) => path.endsWith(`/${a}`)),
  );
  const router = useRouter();
  const [action, setAction] = useState<AcceptanceAction | null>(null);
  const [text, setText] = useState("");
  const [until, setUntil] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  if (offered.length === 0) return null;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!action) return;
    const problem = acceptanceActionProblem(action, { text, until });
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    setError(null);
    const body =
      action === "renew"
        ? { justification: text.trim(), requested_until: until }
        : action === "revoke"
          ? { reason: text.trim() }
          : { note: text.trim() };
    try {
      const response = await fetch(
        `/api/risk-acceptances/${encodeURIComponent(recordId)}/${action}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
      );
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        setError(
          typeof payload?.detail === "string"
            ? payload.detail
            : `The request was refused (HTTP ${response.status}).`,
        );
        return;
      }
      setDone(
        action === "renew"
          ? `Renewal proposed as approval request ${payload?.approval_request_id ?? ""}. This record stands until it is decided.`
          : action === "revoke"
            ? `Revoked. ${payload?.findings_reopened ?? 0} finding(s) re-opened.`
            : "Interim review recorded.",
      );
      setAction(null);
      setText("");
      router.refresh();
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  const button = "min-h-11 border px-3 font-mono text-[12px] font-bold";

  return (
    <div className="mt-3 flex flex-col gap-2 border-t border-rule-soft pt-3">
      <div role="group" aria-label="Act on this acceptance" className="flex flex-wrap gap-1.5">
        {offered.map((a) => (
          <button
            key={a}
            type="button"
            aria-pressed={action === a}
            onClick={() => {
              setAction(a);
              setError(null);
              setDone(null);
            }}
            className={`${button} ${
              action === a
                ? a === "revoke"
                  ? "border-critical bg-critical-wash text-critical"
                  : "border-accent bg-accent-wash text-accent"
                : "border-rule text-ink-2 hover:border-accent hover:text-accent"
            }`}
          >
            {a === "interim-review" ? "Interim review" : a === "renew" ? "Renew" : "Revoke"}
          </button>
        ))}
      </div>
      {action ? (
        <form onSubmit={submit} className="flex flex-col gap-2" noValidate>
          <label className="flex flex-col gap-1">
            <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-ink-3">
              {COPY[action].field} (required)
            </span>
            <textarea
              rows={2}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={COPY[action].placeholder}
              className="border border-rule bg-paper p-2 text-[13px] text-ink placeholder:text-ink-3"
            />
          </label>
          {action === "renew" ? (
            <label className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-ink-3">
                New expiry
              </span>
              <input
                type="date"
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                className="min-h-11 border border-rule bg-paper p-1 font-mono text-[13px] text-ink"
              />
            </label>
          ) : null}
          <button
            type="submit"
            disabled={busy}
            className={`${button} self-start ${
              action === "revoke"
                ? "border-critical bg-critical-wash text-critical"
                : "border-accent bg-accent-wash text-accent"
            } disabled:opacity-50`}
          >
            {busy ? "Sending…" : COPY[action].button}
          </button>
        </form>
      ) : null}
      {error ? (
        <p role="alert" className="text-[13px] text-critical">
          {error}
        </p>
      ) : null}
      {done ? <p className="text-[13px] text-pass">{done}</p> : null}
    </div>
  );
}
