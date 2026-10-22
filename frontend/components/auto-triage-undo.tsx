"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { undoBody } from "@/lib/auto-triage";

/**
 * Put back what auto-triage closed (TheHub #60888, D-169).
 *
 * One click opens a reason field, a second sends it: the reason is audited
 * with the undo, and "the platform was wrong here" is exactly what somebody
 * reviewing the lanes later needs to read. The backend restores the prior
 * status exactly and refuses (409) if the finding has moved since.
 */
export function AutoTriageUndo({ actionId }: { actionId: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [pending, startTransition] = useTransition();

  async function send() {
    setError(null);
    const built = undoBody(reason);
    if (!built.ok) {
      setError(built.error);
      return;
    }
    const response = await fetch(
      `/api/auto-triage/actions/${encodeURIComponent(actionId)}/undo`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(built.body),
      },
    );
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { detail?: string } | null;
      setError(body?.detail ?? `The undo was refused (HTTP ${response.status}).`);
      return;
    }
    setDone(true);
    setOpen(false);
    startTransition(() => router.refresh());
  }

  if (done) {
    return <span className="font-mono text-[11px] text-ink-3">undone - back to its prior status</span>;
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        disabled={pending}
        title="Restore exactly the status this finding had before the platform acted"
        className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:border-accent hover:text-accent disabled:opacity-40"
      >
        undo
      </button>
    );
  }

  return (
    <div className="flex flex-col gap-1">
      <input
        type="text"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        placeholder="why the platform's verdict does not stand"
        className="w-full border border-rule bg-paper px-1.5 py-0.5 font-mono text-[11px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
      />
      <div className="flex flex-wrap items-center gap-1">
        <button
          type="button"
          onClick={() => void send()}
          disabled={pending || !reason.trim()}
          className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40"
        >
          confirm undo
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:text-accent"
        >
          cancel
        </button>
      </div>
      {error ? <p className="text-[11px] text-critical">{error}</p> : null}
    </div>
  );
}
