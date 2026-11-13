"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  DEPLOY_ROUTE,
  MERGE_ROUTE,
  type MergeAsk,
  type MergeOutcome,
} from "@/lib/runsheet-actions";

/**
 * Merge in order and Deploy (TheHub #61142). Rendered only when both switches
 * are on (`showActions`); the page decides, never this component.
 *
 * Each button stays disabled until the operator ticks that they have checked
 * the guards only the host can check, which the step lists. Pressing it
 * queues a request for the host runner; the result says what was queued, or
 * why the server refused, line by line.
 */

type Phase =
  | { kind: "idle" }
  | { kind: "sending" }
  | { kind: "queued"; text: string; outcomes: MergeOutcome[] }
  | { kind: "refused"; text: string; outcomes: MergeOutcome[] };

function detailOf(body: unknown): { text: string; outcomes: MergeOutcome[] } {
  const detail = (body as { detail?: unknown } | null)?.detail;
  if (typeof detail === "string") return { text: detail, outcomes: [] };
  if (detail && typeof detail === "object") {
    const d = detail as { reason?: unknown; outcomes?: unknown };
    return {
      text: typeof d.reason === "string" ? d.reason : "The server refused the request.",
      outcomes: Array.isArray(d.outcomes) ? (d.outcomes as MergeOutcome[]) : [],
    };
  }
  return { text: "The server refused the request.", outcomes: [] };
}

function useAction(route: string) {
  const router = useRouter();
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  async function send(body: unknown, queuedText: string) {
    setPhase({ kind: "sending" });
    try {
      const response = await fetch(route, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      const data: unknown = await response.json().catch(() => null);
      if (response.ok) {
        const outcomes = ((data as { outcomes?: MergeOutcome[] } | null)?.outcomes ?? []);
        setPhase({ kind: "queued", text: queuedText, outcomes });
        router.refresh();
      } else {
        setPhase({ kind: "refused", ...detailOf(data) });
      }
    } catch {
      setPhase({ kind: "refused", text: "Could not reach the dashboard server.", outcomes: [] });
    }
  }
  return { phase, send };
}

function Result({ phase }: { phase: Phase }) {
  if (phase.kind !== "queued" && phase.kind !== "refused") return null;
  return (
    <div
      role="status"
      className={`mt-2 border px-2 py-1.5 text-[13px] ${
        phase.kind === "queued" ? "border-pass bg-pass-wash" : "border-critical bg-critical-wash"
      }`}
    >
      <p className="text-ink">{phase.text}</p>
      {phase.outcomes.length ? (
        <ul className="mt-1 font-mono text-[12px] text-ink-2">
          {phase.outcomes.map((o) => (
            <li key={`${o.repo_full_name}#${o.number}`}>
              {o.repo_full_name}#{o.number}: {o.result}
              {o.reason ? `: ${o.reason}` : ""}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function Acknowledge({
  id,
  notes,
  checked,
  onChange,
}: {
  id: string;
  notes: string[];
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <div className="flex flex-col gap-1">
      {notes.length ? (
        <ul className="list-disc pl-5 text-[12px] text-ink-2">
          {notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      ) : null}
      <span className="flex items-center gap-2 text-[13px] text-ink">
        <input
          type="checkbox"
          id={id}
          checked={checked}
          onChange={(event) => onChange(event.target.checked)}
          className="h-4 w-4 accent-accent"
        />
        <label htmlFor={id}>I have checked the guards only the host can check</label>
      </span>
    </div>
  );
}

const BUTTON =
  "self-start border border-accent bg-accent px-3 py-1.5 text-[13px] font-semibold text-paper " +
  "disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline focus-visible:outline-2 " +
  "focus-visible:outline-offset-2 focus-visible:outline-accent";

export function MergeInOrder({
  batch,
  left,
  notes,
}: {
  batch: MergeAsk[];
  left: number;
  notes: string[];
}) {
  const { phase, send } = useAction(MERGE_ROUTE);
  const [ack, setAck] = useState(false);
  if (batch.length === 0) return null;
  const label = `Merge ${batch.length} in order`;
  return (
    <div className="flex flex-col gap-2 border-t border-rule-soft px-3 py-2">
      <ol className="list-decimal pl-5 font-mono text-[12px] text-ink-2">
        {batch.map((p) => (
          <li key={`${p.repo_full_name}#${p.number}`}>
            {p.repo_full_name}#{p.number} at {p.head_sha.slice(0, 12)}
          </li>
        ))}
      </ol>
      {left ? (
        <p className="text-[12px] text-ink-3">
          {left} more ready: one batch of at most five at a time, then reload.
        </p>
      ) : null}
      <Acknowledge id="merge-ack" notes={notes} checked={ack} onChange={setAck} />
      <button
        type="button"
        className={BUTTON}
        disabled={!ack || phase.kind === "sending" || phase.kind === "queued"}
        onClick={() =>
          send(
            { pull_requests: batch, acknowledged_host_guards: true },
            "Queued for the host runner, in this order. It merges each at the head shown and stops at the first failure.",
          )
        }
      >
        {label}
      </button>
      <Result phase={phase} />
    </div>
  );
}

export function DeployAction({ sha, notes }: { sha: string; notes: string[] }) {
  const { phase, send } = useAction(DEPLOY_ROUTE);
  const [ack, setAck] = useState(false);
  if (!sha) return null;
  return (
    <div className="flex flex-col gap-2 border-t border-rule-soft px-3 py-2">
      <Acknowledge id="deploy-ack" notes={notes} checked={ack} onChange={setAck} />
      <button
        type="button"
        className={BUTTON}
        disabled={!ack || phase.kind === "sending" || phase.kind === "queued"}
        onClick={() =>
          send(
            { sha, acknowledged_host_guards: true },
            "Queued for the host runner, which checks the deploy lock and the Delivery hold first.",
          )
        }
      >
        Deploy {sha.slice(0, 12)}
      </button>
      <Result phase={phase} />
    </div>
  );
}
