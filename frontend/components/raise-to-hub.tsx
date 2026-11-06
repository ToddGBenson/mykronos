"use client";

/**
 * "Raise in TheHub" from a failing lane, a health dependency row or a finding
 * (TheHub #60911). It opens a Hub incident or a backlog story with the
 * evidence MyKronos holds, which the backend builds. Once raised, the row
 * shows the linked Hub id and its live status.
 */

import { useState } from "react";

import { hubLinkText, type RaiseKind, type RaisedLink } from "@/lib/raise-to-hub";

type Draft = { title: string; evidence: string };

const BUTTON =
  "border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-50";

export function RaiseToHub({
  kind,
  subject,
  link,
}: {
  kind: RaiseKind;
  subject: string;
  link: RaisedLink | null | undefined;
}) {
  const [draft, setDraft] = useState<Draft | null>(null);
  const [title, setTitle] = useState("");
  const [note, setNote] = useState("");
  const [as, setAs] = useState<"incident" | "story">("incident");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [raised, setRaised] = useState<RaisedLink | null>(link ?? null);

  if (raised) {
    return (
      <span
        data-raise-kind={kind}
        className="font-mono text-[11px] text-ink-2"
        title={`Raised by ${raised.raised_by}${raised.raised_at ? ` at ${raised.raised_at.slice(0, 16)}` : ""}`}
      >
        {hubLinkText(raised)} · by {raised.raised_by}
      </span>
    );
  }

  async function open() {
    setBusy(true);
    setError(null);
    try {
      const query = new URLSearchParams({ kind, subject });
      const response = await fetch(`/api/raise/draft?${query}`);
      const body = (await response.json()) as Draft & { detail?: string };
      if (!response.ok) throw new Error(body.detail ?? `HTTP ${response.status}`);
      setDraft(body);
      setTitle(body.title);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/raise", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind, subject, raise_as: as, title, note: note || null }),
      });
      const body = (await response.json()) as { hub_kind: string; hub_id: number; detail?: string };
      if (!response.ok) throw new Error(body.detail ?? `HTTP ${response.status}`);
      setRaised({
        subject,
        hub_kind: body.hub_kind,
        hub_id: body.hub_id,
        status: "open",
        raised_by: "you",
        raised_at: new Date().toISOString(),
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <span data-raise-kind={kind} className="inline-flex flex-col gap-1">
      {draft ? (
        <span className="flex flex-col gap-1 border border-rule bg-paper-2 p-2 text-[12px]">
          <label className="flex flex-col gap-0.5">
            <span className="text-ink-3">Title</span>
            <input
              className="border border-rule bg-paper px-1 font-mono text-[12px]"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              maxLength={255}
            />
          </label>
          <label className="flex flex-col gap-0.5">
            <span className="text-ink-3">Note (optional, above the evidence)</span>
            <textarea
              className="border border-rule bg-paper px-1 text-[12px]"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              rows={2}
            />
          </label>
          <pre className="max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[11px] text-ink-3">
            {draft.evidence}
          </pre>
          <span className="flex items-center gap-2">
            <select
              className="border border-rule bg-paper font-mono text-[11px]"
              value={as}
              onChange={(e) => setAs(e.target.value as "incident" | "story")}
              aria-label="Raise as"
            >
              <option value="incident">incident</option>
              <option value="story">backlog story</option>
            </select>
            <button type="button" className={BUTTON} disabled={busy || !title.trim()} onClick={submit}>
              Raise
            </button>
            <button type="button" className={BUTTON} disabled={busy} onClick={() => setDraft(null)}>
              Cancel
            </button>
          </span>
        </span>
      ) : (
        <button type="button" className={BUTTON} disabled={busy} onClick={open}>
          Raise in TheHub
        </button>
      )}
      {error ? <span className="text-[11px] text-critical">{error}</span> : null}
    </span>
  );
}
