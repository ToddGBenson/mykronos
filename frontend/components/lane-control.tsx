"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { type CheckLane, laneActionBody, laneControl } from "@/lib/checks";

/**
 * Retire a scan lane on purpose, or restore one (TheHub #60816).
 *
 * A lane the configuration still lists and nobody runs reads stale, because
 * from the outside it is indistinguishable from a broken one. Retiring says
 * which it is. One click opens a reason field, a second sends it; the backend
 * takes it only from a person and audits it with the reason.
 */
export function LaneControl({
  repoId,
  capability,
  lane,
}: {
  repoId: string;
  capability: string;
  lane: CheckLane;
}) {
  const router = useRouter();
  const action = laneControl(lane);
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  if (action === null) return null;

  async function send() {
    if (action === null) return;
    setError(null);
    const built = laneActionBody(lane, reason);
    if (!built.ok) {
      setError(built.error);
      return;
    }
    const response = await fetch(
      `/api/repos/${encodeURIComponent(repoId)}/checks/${encodeURIComponent(capability)}/lanes/${action}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(built.body),
      },
    );
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { detail?: string } | null;
      setError(body?.detail ?? `Refused (HTTP ${response.status}).`);
      return;
    }
    setOpen(false);
    setReason("");
    startTransition(() => router.refresh());
  }

  const label = action === "retire" ? "retire lane" : "restore lane";
  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        disabled={pending}
        title={
          action === "retire"
            ? "Say this lane is deliberately unused, so it reads retired rather than stale"
            : "Withdraw the retirement: the lane is expected to report again"
        }
        className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:border-accent hover:text-accent disabled:opacity-40"
      >
        {label}
      </button>
    );
  }

  return (
    <div className="flex flex-col gap-1">
      <input
        type="text"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        placeholder={action === "retire" ? "why nobody runs it any more" : "why it is back"}
        className="w-full min-w-[24ch] border border-rule bg-paper px-1.5 py-0.5 font-mono text-[11px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
      />
      <div className="flex flex-wrap items-center gap-1">
        <button
          type="button"
          onClick={() => void send()}
          disabled={pending || !reason.trim()}
          className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40"
        >
          confirm {label}
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:text-accent"
        >
          cancel
        </button>
      </div>
      {error ? <span className="font-mono text-[11px] text-critical">{error}</span> : null}
    </div>
  );
}
