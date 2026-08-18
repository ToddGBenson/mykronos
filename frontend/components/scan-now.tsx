"use client";

/**
 * On-demand scan dispatch (spec 17 §2.5).
 *
 * Fire-and-forget on purpose, and the result panel says so: neither GitHub's
 * `workflow_dispatch` API nor Concourse's build-trigger API hands back a run
 * to poll, so this reports what was *attempted* and points at where the new
 * run will actually show up — the Pipeline stages/Enabled jobs sections on
 * this same tab — rather than pretending to watch it happen.
 */

import { useState } from "react";

import type { paths } from "@/lib/api-types";

type ScanResult =
  paths["/api/repos/{repo_id}/scan"]["post"]["responses"]["200"]["content"]["application/json"];

export function ScanNowButton({
  repoId,
  capabilities,
  label = "scan now",
}: {
  repoId: string;
  /** Scope the dispatch to these capabilities only — the Test Harness tab's
   *  "run tests" reuses this component rather than a second copy of it, so
   *  clicking it there does not also kick off a security scan. Omitted (the
   *  default) dispatches every enabled scanning capability, unchanged. */
  capabilities?: string[];
  label?: string;
}) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const query = (capabilities ?? [])
        .map((c) => `capabilities=${encodeURIComponent(c)}`)
        .join("&");
      const response = await fetch(
        `/api/repos/${repoId}/scan${query ? `?${query}` : ""}`,
        { method: "POST" },
      );
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        setError(
          typeof body?.detail === "string"
            ? body.detail
            : `The request was refused (HTTP ${response.status}).`,
        );
        return;
      }
      setResult(body as ScanResult);
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-1.5">
      <button
        type="button"
        onClick={run}
        disabled={busy}
        className={`self-start border border-rule px-2 py-1 font-mono text-[10px] text-ink-2 hover:border-accent hover:text-accent ${
          busy ? "opacity-40" : ""
        }`}
      >
        {busy ? "dispatching…" : label}
      </button>

      {error ? <p className="font-mono text-[10px] text-critical">{error}</p> : null}

      {result ? (
        <p className="max-w-prose font-mono text-[10px] text-ink-3">
          {result.detail}
          {result.dispatched.length > 0 ? (
            <>
              {" "}
              New runs will appear below — dispatched, not run yet — once each
              completes.
            </>
          ) : null}
          {result.failed.length > 0 ? (
            <span className="text-high"> Failed: {result.failed.join(", ")}.</span>
          ) : null}
        </p>
      ) : null}
    </div>
  );
}
