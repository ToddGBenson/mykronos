"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

/**
 * Confirm or reject what the classifier concluded about one finding (B-020).
 *
 * The classifier labels findings and deliberately cannot act on them: a
 * machine that could set `false_positive` would eventually dismiss a real
 * finding, silently. So the label waits for a person — and before this, the
 * only way to answer it was to open the right repository, find the row and
 * disposition it by hand. 43 dismissals had ever been recorded, all of them
 * sast and secrets, against 234 open container findings.
 *
 * **Both answers are offered, and neither is the default.** Agreeing already
 * left a trace; disagreeing left none, so a classifier calling real findings
 * false positives was indistinguishable from one nobody had reviewed. A
 * verdict nothing ever contradicts is a verdict nobody is checking.
 *
 * Confirming demands a reason, because that is what dampening reads —
 * `min_observations` human reasons, not clicks. The button stays disabled
 * until there is one rather than failing at the backend, which is the same
 * thing said earlier and more kindly.
 */
export function ClassificationReview({
  findingId,
  classification,
  rationale,
}: {
  findingId: string;
  classification: string;
  rationale: string;
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<"agreed" | "rejected" | null>(null);
  const [pending, startTransition] = useTransition();

  // Only the classifier's own false-positive guess is confirmable here.
  // Agreeing with `needs_human_judgment` would dismiss a finding it
  // explicitly declined to judge, which the backend refuses with a 409 —
  // so the affordance is not offered in the first place.
  const confirmable = classification === "likely_false_positive";

  async function send(agrees: boolean) {
    setError(null);
    const response = await fetch(
      `/api/findings/${encodeURIComponent(findingId)}/classification-review`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agrees, reason }),
      },
    );
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as
        | { detail?: string }
        | null;
      setError(body?.detail ?? `The review was refused (HTTP ${response.status}).`);
      return;
    }
    setDone(agrees ? "agreed" : "rejected");
    setOpen(false);
    // The row's status or the queue's contents have changed underneath us.
    startTransition(() => router.refresh());
  }

  if (done) {
    return (
      <span className="font-mono text-[11px] text-ink-3">
        {done === "agreed" ? "dismissed" : "kept — classifier rejected"}
      </span>
    );
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        disabled={pending}
        title={rationale || "Review this classification"}
        className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:border-accent hover:text-accent disabled:opacity-40"
      >
        review
      </button>
    );
  }

  return (
    <div className="flex flex-col gap-1">
      {rationale ? (
        <p className="max-w-[42ch] text-[11px] leading-snug text-ink-3">{rationale}</p>
      ) : null}
      <input
        type="text"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        placeholder="why — recorded either way"
        className="w-full border border-rule bg-paper px-1.5 py-0.5 font-mono text-[11px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
      />
      <div className="flex flex-wrap items-center gap-1">
        {confirmable ? (
          <button
            type="button"
            onClick={() => void send(true)}
            disabled={pending || !reason.trim()}
            title={
              reason.trim()
                ? "Confirm: dismiss this as a false positive"
                : "A reason is required — dampening reads the reason, not the click"
            }
            className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40"
          >
            agree — dismiss
          </button>
        ) : null}
        <button
          type="button"
          onClick={() => void send(false)}
          disabled={pending}
          title="Reject: this finding is real. Recorded against the classifier, and it does not dampen the rule."
          className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40"
        >
          disagree — it is real
        </button>
        <button
          type="button"
          onClick={() => {
            setOpen(false);
            setError(null);
          }}
          className="px-1 font-mono text-[11px] text-ink-3 hover:text-accent"
        >
          cancel
        </button>
      </div>
      {error ? (
        <p className="max-w-[42ch] text-[11px] leading-snug text-critical">{error}</p>
      ) : null}
    </div>
  );
}
