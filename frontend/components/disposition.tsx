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

/**
 * What an acceptance rests on (spec 24 §3.2).
 *
 * Only `no_vendor_fix` is a premise a scan can contradict, and the sweep
 * re-opens exactly that one when a fixed version appears. The others rest on
 * something no scanner sees, so they end on their review date and not before.
 */
const ACCEPTANCE_REASONS = [
  {
    value: "no_vendor_fix",
    label: "No vendor fix",
    hint: "Re-opens automatically the day a scan reports a fixed version.",
  },
  {
    value: "not_exploitable_here",
    label: "Not exploitable here",
    hint: "Real in general, unreachable in this application.",
  },
  {
    value: "compensating_control",
    label: "Compensating control",
    hint: "Something else already blocks it. Name it in the reason.",
  },
  {
    value: "cost_exceeds_risk",
    label: "Cost exceeds risk",
    hint: "A judgement about effort, not about the finding.",
  },
  { value: "other", label: "Other", hint: "Say why in the reason." },
] as const;

/** A default review date far enough out to be useful and near enough to
 *  actually come round. Ninety days, matching the medium remediation target. */
function defaultReviewDate(): string {
  const when = new Date();
  when.setUTCDate(when.getUTCDate() + 90);
  return when.toISOString().slice(0, 10);
}

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
  const [reasonCode, setReasonCode] = useState<string>(ACCEPTANCE_REASONS[0].value);
  const [acceptedUntil, setAcceptedUntil] = useState<string>(defaultReviewDate());
  const [indefinite, setIndefinite] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const selected = DISPOSITIONS.find((d) => d.value === status);
  const accepting = status === "accepted_risk";
  const selectedReason = ACCEPTANCE_REASONS.find((r) => r.value === reasonCode);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setDone(null);

    const response = await fetch(`/api/findings/${findingId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(
        accepting
          ? {
              status,
              reason,
              accepted_reason_code: reasonCode,
              // Sent as one or the other, never both: the server requires a
              // date unless indefinite is explicitly chosen.
              ...(indefinite ? { indefinite: true } : { accepted_until: acceptedUntil }),
            }
          : { status, reason },
      ),
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
      <p className="text-[13px] text-ink-3">
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
            className={`border px-2 py-1 font-mono text-[12px] ${
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
        <p className="text-[12px] text-ink-3">{selected.hint}</p>
      ) : null}

      {accepting ? (
        <div className="flex flex-col gap-2 border-l-2 border-high bg-high-wash px-2 py-2">
          <label className="flex flex-col gap-1">
            <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-ink-3">
              What this rests on
            </span>
            <select
              value={reasonCode}
              onChange={(event) => setReasonCode(event.target.value)}
              className="border border-rule bg-paper p-1 font-mono text-[13px] text-ink"
            >
              {ACCEPTANCE_REASONS.map((entry) => (
                <option key={entry.value} value={entry.value}>
                  {entry.label}
                </option>
              ))}
            </select>
          </label>
          {selectedReason ? (
            <p className="text-[12px] text-ink-3">{selectedReason.hint}</p>
          ) : null}

          <label className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-ink-3">
              Review on
            </span>
            <input
              type="date"
              value={acceptedUntil}
              disabled={indefinite}
              onChange={(event) => setAcceptedUntil(event.target.value)}
              className="border border-rule bg-paper p-1 font-mono text-[13px] text-ink disabled:opacity-40"
            />
            <label className="flex items-center gap-1 font-mono text-[12px] text-ink-3">
              <input
                type="checkbox"
                checked={indefinite}
                onChange={(event) => setIndefinite(event.target.checked)}
              />
              no review date
            </label>
          </label>
          <p className="text-[12px] leading-relaxed text-ink-3">
            On the review date this returns to the queue with its age intact —
            it is not re-discovered. An acceptance with no end is a decision
            nobody revisits.
          </p>
        </div>
      ) : null}

      <label className="flex flex-col gap-1">
        <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-ink-3">
          Reason
        </span>
        <textarea
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          rows={2}
          placeholder="Why? e.g. generated code directory — this rule always fires here"
          className="border border-rule bg-paper p-2 text-[13px] text-ink placeholder:text-ink-3"
        />
      </label>

      <p className="text-[12px] leading-relaxed text-ink-3">
        Without a reason this is still recorded, but flagged low-confidence and
        excluded from becoming a team or org-wide learning. Reasons are what
        make a dismissal actionable rather than a statistic.
      </p>

      <button
        type="submit"
        disabled={pending}
        className="self-start border border-accent bg-accent-wash px-3 py-1 font-mono text-[12px] font-bold text-accent disabled:opacity-50"
      >
        {pending ? "Recording…" : "Record"}
      </button>

      {error ? <p className="text-[13px] text-critical">{error}</p> : null}
      {done ? <p className="text-[13px] text-pass">{done}</p> : null}
    </form>
  );
}
