"use client";

/**
 * "Auto remediation identified" and a way to act on it (spec 18 §7.3).
 *
 * Fetches a preview on mount — the same call `preview()` makes below, safe to
 * repeat because the fixers are deterministic (re-running produces the same
 * diff). "Create PR" is a separate, explicit click: a preview nobody acts on
 * writes nothing, and generating a fix is the one action here that opens a
 * branch and a pull request on the real repository.
 */

import { useEffect, useState } from "react";

import type { paths } from "@/lib/api-types";

type Preview =
  paths["/api/patchwork/findings/{finding_id}/preview"]["post"]["responses"]["200"]["content"]["application/json"];
type Fix =
  paths["/api/patchwork/findings/{finding_id}/fix"]["post"]["responses"]["200"]["content"]["application/json"];

async function post<T>(url: string): Promise<{ ok: true; data: T } | { ok: false; error: string }> {
  try {
    const response = await fetch(url, { method: "POST" });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      return {
        ok: false,
        error:
          typeof body?.detail === "string"
            ? body.detail
            : `The request was refused (HTTP ${response.status}).`,
      };
    }
    return { ok: true, data: body as T };
  } catch {
    return { ok: false, error: "Could not reach the server." };
  }
}

/**
 * Keyed by `findingId` at both call sites, deliberately: a fresh mount per
 * finding is what lets this effect run once and fetch once, rather than
 * needing to reset five pieces of state by hand when the prop changes under
 * an instance React chose to reuse.
 */
export function RemediationAction({ findingId }: { findingId: string }) {
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [fixing, setFixing] = useState(false);
  const [fix, setFix] = useState<Fix | null>(null);
  const [fixError, setFixError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    post<Preview>(`/api/patchwork/findings/${findingId}/preview`).then((result) => {
      if (cancelled) return;
      setLoading(false);
      if (result.ok) setPreview(result.data);
      else setPreviewError(result.error);
    });
    return () => {
      cancelled = true;
    };
  }, [findingId]);

  async function createPr() {
    setFixing(true);
    setFixError(null);
    const result = await post<Fix>(`/api/patchwork/findings/${findingId}/fix`);
    setFixing(false);
    if (result.ok) setFix(result.data);
    else setFixError(result.error);
  }

  if (loading) {
    return <p className="font-mono text-[11px] text-ink-3">checking for an available fix…</p>;
  }
  if (previewError) {
    return <p className="font-mono text-[11px] text-critical">{previewError}</p>;
  }
  if (!preview) return null;

  if (fix) {
    return (
      <p className="max-w-prose font-mono text-[11px] text-ink-3">
        {fix.stage === "pr_opened" && fix.fix_pr_url ? (
          <>
            <a
              href={fix.fix_pr_url}
              target="_blank"
              rel="noreferrer"
              className="text-accent underline-offset-2 hover:underline"
            >
              draft PR #{fix.fix_pr_number}
            </a>{" "}
            opened. {fix.note}
          </>
        ) : (
          <span className="text-ink-2">{fix.rationale}</span>
        )}
      </p>
    );
  }

  if (preview.stage !== "would_fix") {
    // No fix available — the same rationale text the batch pipeline writes
    // to remediation_events, one vocabulary for "why nothing happened"
    // rather than a second one invented for this panel.
    return (
      <p className="max-w-prose font-mono text-[11px] text-ink-3">{preview.rationale}</p>
    );
  }

  return (
    <div className="flex flex-col gap-1.5">
      <p className="max-w-prose font-mono text-[11px] text-ink-2">
        {preview.fixer_name}
        {typeof preview.fix_confidence === "number"
          ? ` · confidence ${preview.fix_confidence.toFixed(2)}`
          : ""}
      </p>
      {preview.fix_files ? (
        <div className="scroll-x max-h-32 border border-rule bg-paper">
          {Object.entries(preview.fix_files).map(([path, content]) => (
            <pre key={path} className="p-2 font-mono text-[11px] leading-relaxed text-ink-2">
              <span className="text-ink-3">{path}</span>
              {"\n"}
              {content}
            </pre>
          ))}
        </div>
      ) : null}
      <button
        type="button"
        onClick={createPr}
        disabled={fixing}
        className={`self-start border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:border-accent hover:text-accent ${
          fixing ? "opacity-40" : ""
        }`}
      >
        {fixing ? "opening…" : "create PR"}
      </button>
      {fixError ? <p className="font-mono text-[11px] text-critical">{fixError}</p> : null}
    </div>
  );
}
