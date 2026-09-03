"use client";

/**
 * i2i: turn a triaged finding or toxic combination into a dev-ready GitHub
 * issue (spec 17 §7.2). Re-clicking the same subject updates the issue it
 * already opened rather than opening a second one — the result panel says
 * which happened, so a second click doesn't read as "did that work again?"
 */

import { useState } from "react";

import type { paths } from "@/lib/api-types";

type GroomResult =
  paths["/api/triage/{finding_id}/groom"]["post"]["responses"]["200"]["content"]["application/json"];

export function GroomButton({
  url,
  label = "groom as story",
}: {
  /** The proxy route for this subject — one finding or one combination. */
  url: string;
  label?: string;
}) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<GroomResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const response = await fetch(url, { method: "POST" });
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        setError(
          typeof body?.detail === "string"
            ? body.detail
            : `The request was refused (HTTP ${response.status}).`,
        );
        return;
      }
      setResult(body as GroomResult);
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-1">
      <button
        type="button"
        onClick={run}
        disabled={busy}
        className={`self-start border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:border-accent hover:text-accent ${
          busy ? "opacity-40" : ""
        }`}
      >
        {busy ? "grooming…" : label}
      </button>

      {error ? <p className="font-mono text-[11px] text-critical">{error}</p> : null}

      {result ? (
        <p className="max-w-prose font-mono text-[11px] text-ink-3">
          <a
            href={result.github_issue_url}
            target="_blank"
            rel="noreferrer"
            className="text-accent underline-offset-2 hover:underline"
          >
            issue #{result.github_issue_number}
          </a>{" "}
          {result.created ? "opened" : "updated"} —{" "}
          {result.dev_ready ? (
            "dev-ready"
          ) : (
            <span className="text-high">
              needs triage: missing {result.missing_fields.join(", ")}
            </span>
          )}
        </p>
      ) : null}
    </div>
  );
}
