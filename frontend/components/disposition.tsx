"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

/**
 * Recording a human disposition on a finding (spec 10 §2.2).
 *
 * The reason field is not decoration. spec 11 §4: a dismissal without one is
 * still recorded but flagged low-confidence and barred from promotion,
 * because reasons are what make a learning actionable rather than a
 * statistic. The form says so rather than silently downgrading the signal.
 *
 * `fixed` is deliberately not offered. That is an observation the scanners and
 * the reconciler own; letting a person assert it would put a claim in the lake
 * that no scan supports.
 */
const DISPOSITIONS = [
  {
    value: "false_positive",
    label: "False positive",
    hint: "The tool is wrong about this one.",
  },
  {
    value: "accepted_risk",
    label: "Accept risk",
    hint: "Real, but we are choosing to live with it.",
  },
  {
    value: "suppressed",
    label: "Suppress",
    hint: "Do not surface again; not a judgement about validity.",
  },
] as const;

export function DispositionForm({
  findingId,
  currentStatus,
}: {
  findingId: string;
  currentStatus: string;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [status, setStatus] = useState<string>(DISPOSITIONS[0].value);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const selected = DISPOSITIONS.find((d) => d.value === status);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setDone(null);

    const response = await fetch(`/api/findings/${findingId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, reason }),
    });
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      setError(payload.detail ?? "The change was rejected.");
      return;
    }

    setDone(
      payload.reason_supplied
        ? `Recorded as ${status.replace("_", " ")}.`
        : `Recorded as ${status.replace("_", " ")}, but without a reason it is ` +
          "low-confidence and cannot be promoted to a team or org learning.",
    );
    startTransition(() => router.refresh());
  }

  if (currentStatus !== "open") {
    return (
      <p className="text-[11px] text-ink-3">
        Already recorded as{" "}
        <span className="font-mono text-ink-2">{currentStatus.replace("_", " ")}</span>.
        Re-opening is the scanners&rsquo; job: it happens automatically if the
        finding is reported again.
      </p>
    );
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-1.5">
        {DISPOSITIONS.map((disposition) => (
          <button
            key={disposition.value}
            type="button"
            onClick={() => setStatus(disposition.value)}
            aria-pressed={status === disposition.value}
            className={`border px-2 py-1 font-mono text-[10px] ${
              status === disposition.value
                ? "border-accent bg-accent-wash text-accent"
                : "border-rule text-ink-3 hover:border-accent hover:text-accent"
            }`}
          >
            {disposition.label}
          </button>
        ))}
      </div>

      {selected ? (
        <p className="text-[10px] text-ink-3">{selected.hint}</p>
      ) : null}

      <label className="flex flex-col gap-1">
        <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-ink-3">
          Reason
        </span>
        <textarea
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          rows={2}
          placeholder="Why? e.g. generated code directory — this rule always fires here"
          className="border border-rule bg-paper p-2 text-[11px] text-ink placeholder:text-ink-3"
        />
      </label>

      <p className="text-[10px] leading-relaxed text-ink-3">
        Without a reason this is still recorded, but flagged low-confidence and
        excluded from becoming a team or org-wide learning. Reasons are what
        make a dismissal actionable rather than a statistic.
      </p>

      <button
        type="submit"
        disabled={pending}
        className="self-start border border-accent bg-accent-wash px-3 py-1 font-mono text-[10px] font-bold text-accent disabled:opacity-50"
      >
        {pending ? "Recording…" : "Record"}
      </button>

      {error ? <p className="text-[11px] text-critical">{error}</p> : null}
      {done ? <p className="text-[11px] text-pass">{done}</p> : null}
    </form>
  );
}
