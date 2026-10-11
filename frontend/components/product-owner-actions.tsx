"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

/**
 * The Product Owner tab's three writes (spec 35 §4). Each posts to a proxy on
 * this server, which carries the admin token; the backend decides the order
 * of the Hub calls and records every attempt in the audit log. A refusal is
 * shown as the backend sent it, because for a sprint pull that is TheHub's own
 * sentence about which of its rules the story does not meet.
 */

async function post(url: string, body?: unknown): Promise<string | null> {
  const response = await fetch(url, {
    method: "POST",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (response.ok) return null;
  const payload = (await response.json().catch(() => null)) as { detail?: unknown } | null;
  const detail = payload?.detail;
  return typeof detail === "string" && detail
    ? detail
    : `The request was refused (HTTP ${response.status}).`;
}

function useAction() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(url: string, body?: unknown) {
    setError(null);
    setBusy(true);
    try {
      const refusal = await post(url, body);
      if (refusal) {
        setError(refusal);
        return;
      }
      startTransition(() => router.refresh());
    } catch {
      setError("Could not reach this server.");
    } finally {
      setBusy(false);
    }
  }

  return { run, error, disabled: pending || busy };
}

const BUTTON =
  "border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40";

function base(repoId: string): string {
  return `/api/repos/${encodeURIComponent(repoId)}/product-owner`;
}

export function PullIntoSprint({ repoId, storyId }: { repoId: string; storyId: number }) {
  const { run, error, disabled } = useAction();
  return (
    <span className="flex flex-wrap items-baseline gap-2">
      <button
        type="button"
        disabled={disabled}
        onClick={() => void run(`${base(repoId)}/stories/${storyId}/pull`)}
        title="Switches the story's autonomy off in TheHub, then moves it into the sprint"
        className={BUTTON}
      >
        pull into sprint
      </button>
      {error ? <span className="max-w-prose text-[11px] text-critical">{error}</span> : null}
    </span>
  );
}

export function BackToBacklog({ repoId, storyId }: { repoId: string; storyId: number }) {
  const { run, error, disabled } = useAction();
  return (
    <span className="flex flex-wrap items-baseline gap-2">
      <button
        type="button"
        disabled={disabled}
        onClick={() => void run(`${base(repoId)}/stories/${storyId}/return`)}
        className={BUTTON}
      >
        back to backlog
      </button>
      {error ? <span className="max-w-prose text-[11px] text-critical">{error}</span> : null}
    </span>
  );
}

export function RankControls({
  repoId,
  storyId,
  first,
  last,
}: {
  repoId: string;
  storyId: number;
  first: boolean;
  last: boolean;
}) {
  const { run, error, disabled } = useAction();
  return (
    <span className="flex items-baseline gap-1">
      <button
        type="button"
        aria-label="Move up"
        disabled={disabled || first}
        onClick={() => void run(`${base(repoId)}/rank`, { story_id: storyId, direction: "up" })}
        className={BUTTON}
      >
        ↑
      </button>
      <button
        type="button"
        aria-label="Move down"
        disabled={disabled || last}
        onClick={() => void run(`${base(repoId)}/rank`, { story_id: storyId, direction: "down" })}
        className={BUTTON}
      >
        ↓
      </button>
      {error ? <span className="text-[11px] text-critical">{error}</span> : null}
    </span>
  );
}
