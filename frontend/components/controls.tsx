"use client";

/**
 * What stops the things this tab lists (spec 28 §3).
 *
 * A threat model is made of four things — assets, entry points, trust
 * boundaries, mitigations — and this tab had one. Every row on it was a
 * problem, and there was no representation anywhere of "authentication is
 * required on this route" or "these secrets rotate on this cadence". Two
 * consequences, both of which get worse as the platform gets better: the tab
 * can only ever grow more red as scanning improves, and a team that spends a
 * quarter adding controls sees no change at all.
 *
 * **Declared, never verified, and the wording never blurs the two.** A row
 * here says a person asserted this — which is a weaker and clearer claim than
 * a machine implying it, and it is useful the day it ships. What keeps it
 * from being a wiki is that the platform can *contradict* it: an
 * authentication control on a category with open findings underneath is shown
 * as a contradiction rather than resolved, because the platform has no basis
 * to decide whether the control is wrong, bypassed, or narrower than its
 * description — and all three are worth somebody's attention.
 */

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Label, Pill, RelativeTime } from "@/components/primitives";
import type { ThreatModelControl } from "@/lib/api";

const KINDS = [
  "authentication",
  "authorization",
  "input_validation",
  "output_encoding",
  "secrets_management",
  "logging",
  "rate_limiting",
  "encryption",
] as const;

function kindLabel(kind: string) {
  return kind.replace(/_/g, " ");
}

export function ControlList({
  repoId,
  stride,
  controls,
}: {
  repoId: string;
  stride: string;
  controls: ThreatModelControl[];
}) {
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function act(controlId: string, action: "confirm" | "withdraw") {
    setBusy(controlId);
    setError(null);
    try {
      const url =
        action === "confirm"
          ? `/api/repos/${repoId}/controls/${controlId}/confirm`
          : `/api/repos/${repoId}/controls/${controlId}`;
      const response = await fetch(url, {
        method: action === "confirm" ? "POST" : "DELETE",
      });
      if (!response.ok) {
        const body = await response.json().catch(() => null);
        setError(
          typeof body?.detail === "string"
            ? body.detail
            : `The request was refused (HTTP ${response.status}).`,
        );
        return;
      }
      router.refresh();
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="flex flex-col">
      {controls.map((control) => (
        <div
          key={control.control_id}
          className="flex flex-wrap items-baseline gap-x-2 gap-y-1 border-b border-rule-soft px-3 py-2 last:border-b-0"
        >
          <Pill tone="accent">{kindLabel(control.kind)}</Pill>

          <span className="text-[13px] text-ink-2">
            {control.description || <em className="text-ink-3">no description</em>}
          </span>

          {control.evidence_ref ? (
            <span className="font-mono text-[12px] text-ink-3">
              {control.evidence_ref}
            </span>
          ) : (
            // Allowed, and rendered as the weaker claim it is. Refusing it
            // would mean the register only ever holds the controls somebody
            // had time to document.
            <span
              className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3"
              title="Asserted with no file, route, policy or test named."
            >
              no evidence
            </span>
          )}

          {/* A control nothing in the platform can contradict is not a
              verified control, and the tab must not let it look like one. */}
          {!control.checkable ? (
            <span
              className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3"
              title="No capability here can contradict this control, so nothing checks it."
            >
              unchecked
            </span>
          ) : null}

          {control.stale ? (
            <Pill tone="warn">stale</Pill>
          ) : control.last_verified_at ? (
            <span className="font-mono text-[11px] text-ink-3">
              confirmed <RelativeTime value={control.last_verified_at} />
            </span>
          ) : null}

          <span className="ml-auto flex items-center gap-1.5">
            <button
              type="button"
              disabled={busy === control.control_id}
              onClick={() => act(control.control_id, "confirm")}
              className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:border-accent hover:text-accent disabled:opacity-50"
            >
              still true
            </button>
            <button
              type="button"
              disabled={busy === control.control_id}
              onClick={() => act(control.control_id, "withdraw")}
              className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:border-critical hover:text-critical disabled:opacity-50"
            >
              withdraw
            </button>
          </span>

          {control.declared_by ? (
            <span className="w-full font-mono text-[11px] text-ink-3">
              declared by {control.declared_by}
            </span>
          ) : null}
        </div>
      ))}

      {error ? (
        <p className="border-t border-rule-soft px-3 py-1.5 text-[13px] text-critical">
          {error}
        </p>
      ) : null}

      <DeclareControl repoId={repoId} stride={stride} />
    </div>
  );
}

function DeclareControl({ repoId, stride }: { repoId: string; stride: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [kind, setKind] = useState<string>(KINDS[0]);
  const [description, setDescription] = useState("");
  const [evidence, setEvidence] = useState("");

  async function save() {
    setSaving(true);
    setError(null);
    try {
      const response = await fetch(`/api/repos/${repoId}/controls`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          stride,
          kind,
          description: description.trim(),
          evidence_ref: evidence.trim(),
        }),
      });
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        setError(
          typeof body?.detail === "string"
            ? body.detail
            : `The request was refused (HTTP ${response.status}).`,
        );
        return;
      }
      setDescription("");
      setEvidence("");
      setOpen(false);
      router.refresh();
    } catch {
      setError("Could not reach the server.");
    } finally {
      setSaving(false);
    }
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="border-t border-rule-soft px-3 py-1.5 text-left font-mono text-[12px] text-ink-3 hover:text-accent"
      >
        + declare a control for {stride.replace(/_/g, " ")}
      </button>
    );
  }

  return (
    <div className="flex flex-col gap-2 border-t border-rule-soft px-3 py-2">
      <Label>Declare a control</Label>

      <label className="flex flex-col gap-1">
        <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
          Kind
        </span>
        <select
          value={kind}
          onChange={(event) => setKind(event.target.value)}
          className="border border-rule bg-paper px-1.5 py-1 font-mono text-[13px] text-ink"
        >
          {KINDS.map((value) => (
            <option key={value} value={value}>
              {kindLabel(value)}
            </option>
          ))}
        </select>
      </label>

      <label className="flex flex-col gap-1">
        <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
          What it does
        </span>
        <input
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          placeholder="Every route behind the session middleware."
          className="border border-rule bg-paper px-1.5 py-1 text-[13px] text-ink"
        />
      </label>

      <label className="flex flex-col gap-1">
        <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
          Evidence — a file, route, policy or test
        </span>
        <input
          value={evidence}
          onChange={(event) => setEvidence(event.target.value)}
          placeholder="app/middleware/auth.py"
          className="border border-rule bg-paper px-1.5 py-1 font-mono text-[13px] text-ink"
        />
        <span className="text-[12px] leading-relaxed text-ink-3">
          Optional. A control without one is recorded as asserted rather than
          referenced — worth having, and shown as the weaker claim.
        </span>
      </label>

      {error ? <p className="text-[13px] text-critical">{error}</p> : null}

      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={saving}
          onClick={save}
          className="border border-accent px-2 py-0.5 font-mono text-[12px] text-accent hover:bg-accent-wash disabled:opacity-50"
        >
          {saving ? "recording…" : "declare"}
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="font-mono text-[12px] text-ink-3 hover:text-ink"
        >
          cancel
        </button>
      </div>
    </div>
  );
}
