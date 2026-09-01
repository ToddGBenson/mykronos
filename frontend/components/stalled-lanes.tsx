"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import type { StalledLane } from "@/lib/api";

/**
 * Lanes that cannot close findings, and the one button that acts on each
 * (D-098).
 *
 * A finding closes only after two consecutive *successful* scans observe its
 * absence (spec 05 §5). So a lane that is failing — or that quietly stopped
 * running — freezes its findings open however thoroughly the defect was
 * fixed. On 2026-09-01 that was 431 of 475 open findings across the estate,
 * and every other surface in the platform reported them as open work somebody
 * was neglecting. The portfolio ranks repositories, the worklist ranks
 * findings, the CI view shows job status; none of them joins "this lane is
 * broken" to "so these findings cannot close".
 *
 * **The two reasons are not rendered the same, and that is load-bearing.** A
 * silent lane was working when it stopped, so dispatching it is the whole fix
 * and the button says so. A failing lane will fail again — re-running it
 * closes nothing and looks like action, so the button is still offered (a
 * person may well be re-running it to read the new logs) and the caveat is
 * next to it rather than discovered afterwards.
 */
export function StalledLanes({ lanes }: { lanes: StalledLane[] }) {
  if (!lanes.length) {
    return (
      <p className="font-mono text-[10px] text-ink-3">
        Every lane is reporting. Findings can close.
      </p>
    );
  }

  // A lane holding nothing open is still broken and still worth knowing
  // about, but it must not push a lane holding 213 findings down the page.
  const holding = lanes.filter((lane) => lane.open_findings > 0);
  const idle = lanes.filter((lane) => lane.open_findings === 0);

  return (
    <div className="flex flex-col gap-3">
      {holding.map((lane) => (
        <Lane key={`${lane.repo_full_name}:${lane.capability}`} lane={lane} />
      ))}
      {idle.length ? (
        <p className="text-[10px] leading-snug text-ink-3">
          Also stalled, holding nothing open:{" "}
          {idle.map((lane) => `${lane.repo_full_name} ${lane.capability}`).join(", ")}.
          Nothing is stuck behind these, but they are not watching either.
        </p>
      ) : null}
    </div>
  );
}

function Lane({ lane }: { lane: StalledLane }) {
  const router = useRouter();
  const [state, setState] = useState<"idle" | "dispatched" | "error">("idle");
  const [message, setMessage] = useState("");
  const [pending, startTransition] = useTransition();

  const failing = lane.reason === "failing";
  const state_line = failing
    ? `${lane.streak_capped ? "at least " : ""}${lane.consecutive_failures} consecutive ` +
      `failures, ${
        lane.last_success
          ? `last success ${lane.last_success.slice(0, 10)}`
          : "no successful run on record"
      }`
    : `silent for ${Math.round(lane.days_since_run)} days (usually every ${cadence(
        lane.usual_gap_days,
      )})`;

  async function dispatch() {
    setMessage("");
    // The backend endpoint is keyed by repo id, and `repo_full_name` is what
    // the lake holds. They are the same string for a repository asset (spec
    // 14 §5), which is what makes this safe.
    const response = await fetch(
      `/api/repos/${encodeURIComponent(lane.repo_full_name)}/scan` +
        `?capabilities=${encodeURIComponent(lane.capability)}`,
      { method: "POST" },
    );
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { detail?: string } | null;
      setState("error");
      setMessage(body?.detail ?? `The dispatch was refused (HTTP ${response.status}).`);
      return;
    }
    setState("dispatched");
    startTransition(() => router.refresh());
  }

  return (
    <div className="border-l-2 border-rule pl-3">
      <div className="flex flex-wrap items-baseline gap-x-2">
        <span className="font-mono text-[11px] text-ink">{lane.capability}</span>
        <span className="font-mono text-[10px] text-ink-2">{lane.repo_full_name}</span>
        <span className="font-mono text-[9px] text-ink-3">— {state_line}</span>
      </div>

      <p className="mt-0.5 text-[10px] text-ink-2">
        holding <strong className="text-ink">{lane.open_findings}</strong> finding
        {lane.open_findings === 1 ? "" : "s"} open
      </p>
      {lane.detail ? (
        <p className="mt-0.5 max-w-[70ch] font-mono text-[9px] leading-snug text-ink-3">
          {lane.detail}
        </p>
      ) : null}

      <div className="mt-1 flex flex-wrap items-center gap-2">
        {state === "dispatched" ? (
          <span className="font-mono text-[9px] text-ink-3">
            dispatched — two successful runs will close what is stuck
          </span>
        ) : (
          <button
            type="button"
            onClick={() => void dispatch()}
            disabled={pending}
            title={lane.action.effect}
            className="border border-rule px-1.5 py-0.5 font-mono text-[9px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40"
          >
            re-run {lane.capability}
          </button>
        )}
        <span className="max-w-[52ch] text-[9px] leading-snug text-ink-3">
          {failing
            ? "Repair the job first — a re-run of a broken workflow fails again and closes nothing."
            : "The lane was working when it stopped, so this is the fix."}
        </span>
      </div>

      {state === "error" ? (
        <p className="mt-1 max-w-[52ch] text-[9px] leading-snug text-critical">{message}</p>
      ) : null}
    </div>
  );
}

/** "every 5 hours", not "every 0.2 days" — nobody converts that in their head. */
function cadence(days: number): string {
  if (days >= 1) return `${Math.round(days)} day${days >= 2 ? "s" : ""}`;
  const hours = days * 24;
  return hours >= 1 ? `${Math.round(hours)} hours` : "few minutes";
}
