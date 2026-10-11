"use client";

import { useState } from "react";

/**
 * Offer a starter `.sdlc/process.yaml` to a repository that declares none
 * (spec 35 §7.2). Choosing one asks the backend to open a draft pull request;
 * nothing is committed to the default branch, and the tab keeps saying the
 * repository declares no process until that pull request is merged.
 */

type Template = { id: string; label: string; summary: string };
type Opened = { pr_url: string; pr_number: number; created: boolean };

const BUTTON =
  "border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40";

export function TemplatePicker({
  repoId,
  templates,
}: {
  repoId: string;
  templates: Template[];
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opened, setOpened] = useState<Opened | null>(null);

  async function choose(template: string) {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/repos/${encodeURIComponent(repoId)}/product-owner/template`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ template }),
        },
      );
      const payload = (await response.json().catch(() => null)) as
        | (Opened & { detail?: unknown })
        | null;
      if (!response.ok || !payload) {
        const detail = payload?.detail;
        setError(
          typeof detail === "string" && detail
            ? detail
            : `The request was refused (HTTP ${response.status}).`,
        );
        return;
      }
      setOpened(payload);
    } catch {
      setError("Could not reach this server.");
    } finally {
      setBusy(false);
    }
  }

  if (opened) {
    return (
      <p className="px-3 py-2 text-[12px] text-ink-2">
        {opened.created ? "Opened" : "Already open:"} draft pull request{" "}
        <a href={opened.pr_url} rel="noreferrer" className="font-mono text-accent">
          #{opened.pr_number}
        </a>
        . Edit it, then merge it to declare this repository&apos;s process.
      </p>
    );
  }

  return (
    <div className="flex flex-col">
      {templates.map((template) => (
        <div
          key={template.id}
          className="flex flex-wrap items-baseline gap-2.5 border-t border-rule-soft px-3 py-1.5"
        >
          <span className="font-mono text-[12px] font-bold text-ink">{template.label}</span>
          <span className="text-[12px] text-ink-2">{template.summary}</span>
          <button
            type="button"
            disabled={busy}
            onClick={() => void choose(template.id)}
            className={`ml-auto ${BUTTON}`}
          >
            open template PR
          </button>
        </div>
      ))}
      {error ? <p className="px-3 py-1.5 text-[11px] text-critical">{error}</p> : null}
    </div>
  );
}
