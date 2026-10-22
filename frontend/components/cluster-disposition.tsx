"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import {
  CLUSTER_VERDICTS,
  clusterDispositionBody,
  dispositionOutcomeLine,
} from "@/lib/clusters";

/**
 * One verdict for every member of a cluster (TheHub #60887, D-168).
 *
 * Sends the member ids the person was shown, so the backend can refuse when
 * the cluster changed underneath them. The reason is required and recorded on
 * every member's own audit entry. When the caller would need an approval for
 * any member, the backend raises one request for the cluster and closes
 * nothing; the line under the form says which happened.
 */
export function ClusterDisposition({
  clusterId,
  memberIds,
}: {
  clusterId: string;
  memberIds: string[];
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [verdict, setVerdict] = useState<string>(CLUSTER_VERDICTS[0].value);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  async function send() {
    setError(null);
    const built = clusterDispositionBody(verdict, reason, memberIds);
    if (!built.ok) {
      setError(built.error);
      return;
    }
    const response = await fetch(
      `/api/triage/clusters/${encodeURIComponent(clusterId)}/disposition`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(built.body),
      },
    );
    const body = (await response.json().catch(() => null)) as
      | { detail?: string; outcome?: string; applied?: string[]; refused?: Record<string, string>; tier?: string | null }
      | null;
    if (!response.ok || !body?.outcome) {
      setError(body?.detail ?? `The disposition was refused (HTTP ${response.status}).`);
      return;
    }
    setDone(dispositionOutcomeLine({ ...body, outcome: body.outcome }));
    setOpen(false);
    startTransition(() => router.refresh());
  }

  if (done) {
    return <span className="font-mono text-[11px] text-ink-3">{done}</span>;
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        disabled={pending}
        title={`One verdict for all ${memberIds.length} member(s), recorded on each`}
        className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:border-accent hover:text-accent disabled:opacity-40"
      >
        decide for all {memberIds.length}
      </button>
    );
  }

  return (
    <div className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-1">
        {CLUSTER_VERDICTS.map((entry) => (
          <label key={entry.value} className="flex items-center gap-1 font-mono text-[11px] text-ink-2">
            <input
              type="radio"
              name={`verdict-${clusterId}`}
              value={entry.value}
              checked={verdict === entry.value}
              onChange={() => setVerdict(entry.value)}
            />
            {entry.label}
          </label>
        ))}
      </div>
      <input
        type="text"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        placeholder="why - recorded on every member"
        className="w-full border border-rule bg-paper px-1.5 py-0.5 font-mono text-[11px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
      />
      <div className="flex flex-wrap items-center gap-1">
        <button
          type="button"
          onClick={() => void send()}
          disabled={pending || !reason.trim()}
          className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40"
        >
          record for {memberIds.length}
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
