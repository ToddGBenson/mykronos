"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { EmptyState, Label, Pill } from "@/components/primitives";
import type { RepoSurfaces, Surface } from "@/lib/api";
import {
  requirementsLabel,
  SELECTOR_KINDS,
  SELECTOR_LABELS,
  SELECTOR_PLACEHOLDERS,
  selectorChips,
  selectorsFromInputs,
  type SelectorKind,
} from "@/lib/selectors";

/**
 * Assets, entry points and trust boundaries (B-029).
 *
 * The Controls panel closed one quarter of a threat model: what stops the
 * things this tab lists. This is the other three, and the argument is the same
 * one step earlier — a tab built only from findings can say what was found and
 * never what is *at stake*. "Twelve mediums in the payments service" and
 * "twelve mediums in the internal changelog renderer" render identically, and
 * they are not the same problem.
 *
 * **Declared, never verified, and the wording never blurs the two.** Nothing
 * in the platform can confirm that a database holds customer records. A row
 * here is a person asserting it, which is weaker and clearer than a machine
 * implying it, and useful the day somebody types it.
 *
 * The header says how much of this is a model rather than an inventory:
 * `unknowns` counts declared rows still carrying an unanswered question, and
 * a repository with nine assets and nine unknown sensitivities has a list,
 * not a threat model.
 */

const KINDS = [
  { id: "asset", label: "Asset", hint: "Something worth reaching" },
  { id: "entry_point", label: "Entry point", hint: "A way in" },
  { id: "trust_boundary", label: "Trust boundary", hint: "Where trust changes" },
] as const;

const EXPOSURES = ["unknown", "internet", "internal", "local"] as const;
const LEVELS = ["", "H", "M", "L"] as const;
const SENSITIVITIES = [
  "unknown",
  "pii",
  "financial",
  "credentials",
  "source",
  "public",
] as const;

export function Surfaces({ repoId, data }: { repoId: string; data: RepoSurfaces }) {
  return (
    <section className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline gap-3">
        <Label>What this repository is</Label>
        <span className="font-mono text-[12px] text-ink-3">
          {data.total} declared
        </span>
        {data.internet_facing > 0 ? (
          <Pill tone="warn">{data.internet_facing} internet-facing</Pill>
        ) : null}
        {data.unknowns > 0 ? (
          <Pill tone="muted">{data.unknowns} unanswered</Pill>
        ) : null}
        {!data.complete && data.total > 0 ? (
          <span className="font-mono text-[11px] text-ink-3">
            incomplete — a model needs all three
          </span>
        ) : null}
        <ManifestSync repoId={repoId} />
      </div>

      <p className="max-w-prose text-[12px] leading-relaxed text-ink-2">
        <strong className="text-ink">Declared, not verified.</strong> Nothing
        here can confirm that a database holds customer records or that a port
        is reachable from outside. These are assertions a person made, which is
        weaker and clearer than a machine implying the same thing — and the
        findings above are worth more when the platform knows what they are
        findings <em>in</em>.
      </p>

      {data.total === 0 ? (
        <EmptyState
          title="Nothing declared yet"
          detail="Findings say what was found. Assets, entry points and trust boundaries say what is at stake — without them, a medium in the payments service and a medium in the changelog renderer are the same row."
        />
      ) : (
        <div className="flex flex-col gap-3">
          {KINDS.map((kind) => {
            const rows =
              kind.id === "asset"
                ? data.assets
                : kind.id === "entry_point"
                  ? data.entry_points
                  : data.trust_boundaries;
            return (
              <Group
                key={kind.id}
                repoId={repoId}
                title={kind.label}
                hint={kind.hint}
                rows={rows}
                showSensitivity={kind.id === "asset"}
              />
            );
          })}
        </div>
      )}

      <DeclareForm repoId={repoId} />
    </section>
  );
}

function Group({
  repoId,
  title,
  hint,
  rows,
  showSensitivity,
}: {
  repoId: string;
  title: string;
  hint: string;
  rows: Surface[];
  showSensitivity: boolean;
}) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-baseline gap-2">
        <span className="font-mono text-[12px] font-bold text-ink">{title}</span>
        <span className="font-mono text-[11px] text-ink-3">{hint}</span>
        <span className="font-mono text-[11px] text-ink-3">· {rows.length}</span>
      </div>
      {rows.length === 0 ? (
        <p className="font-mono text-[11px] text-ink-3">
          none declared — this part of the model is missing
        </p>
      ) : (
        rows.map((row) => (
          <SurfaceRow key={row.id} repoId={repoId} row={row} showSensitivity={showSensitivity} />
        ))
      )}
    </div>
  );
}

function SurfaceRow({
  repoId,
  row,
  showSensitivity,
}: {
  repoId: string;
  row: Surface;
  showSensitivity: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  async function withdraw() {
    setError(null);
    const response = await fetch(
      `/api/repos/${encodeURIComponent(repoId)}/surfaces/${encodeURIComponent(row.id)}`,
      { method: "DELETE" },
    );
    if (!response.ok && response.status !== 204) {
      setError(`Could not withdraw it (HTTP ${response.status}).`);
      return;
    }
    startTransition(() => router.refresh());
  }

  return (
    <div className="flex flex-wrap items-baseline gap-2 border-b border-rule-soft py-1 last:border-0">
      <span className="font-mono text-[12px] text-ink">{row.name}</span>
      <span
        className={`font-mono text-[11px] ${
          row.exposure === "internet"
            ? "text-high"
            : row.exposure === "unknown"
              ? "text-ink-3"
              : "text-ink-2"
        }`}
        title={
          row.exposure === "unknown"
            ? "Nobody has said how reachable this is. Not the same as 'internal'."
            : undefined
        }
      >
        {row.exposure}
      </span>
      {showSensitivity ? (
        <span className="font-mono text-[11px] text-ink-2">{row.sensitivity}</span>
      ) : null}
      {row.description ? (
        <span className="max-w-[46ch] text-[11px] leading-snug text-ink-3">
          {row.description}
        </span>
      ) : null}
      {row.evidence_ref ? (
        <span className="font-mono text-[11px] text-ink-3">{row.evidence_ref}</span>
      ) : null}
      {requirementsLabel(row) ? (
        <span
          className="font-mono text-[11px] text-ink-2"
          title="CVSS Security Requirements this asset overrides. A dash is derived, not set."
        >
          {requirementsLabel(row)}
        </span>
      ) : null}
      {row.read_only ? (
        <span title="Declared in .sdlc/threat-model.yaml. Change it there, by pull request.">
          <Pill tone="muted">manifest</Pill>
        </span>
      ) : (
        <button
          type="button"
          onClick={() => void withdraw()}
          disabled={pending}
          title="Withdraw this declaration — a correction, not a deletion of evidence"
          className="ml-auto border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:border-critical hover:text-critical disabled:opacity-40"
        >
          withdraw
        </button>
      )}
      <SelectorLine row={row} />
      {error ? <span className="text-[11px] text-critical">{error}</span> : null}
    </div>
  );
}

/**
 * Where the surface is (TheHub #60825). A surface with no selectors is shown
 * as "not located" rather than nothing: it matches no finding, so the
 * findings above cannot be placed inside it.
 */
function SelectorLine({ row }: { row: Surface }) {
  const chips = selectorChips(row.selectors);
  if (chips.length === 0) {
    return (
      <span className="w-full font-mono text-[11px] text-ink-3">
        not located — no selectors, so no finding is placed in it
      </span>
    );
  }
  return (
    <span className="flex w-full flex-wrap gap-1">
      {chips.map((chip) => (
        <span
          key={`${chip.kind}:${chip.value}`}
          className="border border-rule-soft px-1 font-mono text-[11px] text-ink-2"
          title={SELECTOR_LABELS[chip.kind]}
        >
          <span className="text-ink-3">{SELECTOR_LABELS[chip.kind]} </span>
          {chip.value}
        </span>
      ))}
    </span>
  );
}

/**
 * Re-read `.sdlc/threat-model.yaml` now rather than waiting for the job. An
 * invalid file changes nothing and the reason is shown, word for word.
 */
function ManifestSync({ repoId }: { repoId: string }) {
  const router = useRouter();
  const [message, setMessage] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  async function sync() {
    setMessage(null);
    const response = await fetch(
      `/api/repos/${encodeURIComponent(repoId)}/threat-model/sync`,
      { method: "POST" },
    );
    const body = (await response.json().catch(() => null)) as {
      state?: string;
      error?: string | null;
      applied?: boolean;
      detail?: string;
    } | null;
    if (!response.ok || !body) {
      setMessage(body?.detail ?? `The sync was refused (HTTP ${response.status}).`);
      return;
    }
    setMessage(
      body.applied
        ? body.state === "absent"
          ? "No .sdlc/threat-model.yaml on the default branch."
          : "Synced from .sdlc/threat-model.yaml."
        : `Not applied (${body.state}): ${body.error ?? "no reason given"}`,
    );
    startTransition(() => router.refresh());
  }

  return (
    <span className="ml-auto flex items-baseline gap-2">
      {message ? <span className="text-[11px] text-ink-3">{message}</span> : null}
      <button
        type="button"
        onClick={() => void sync()}
        disabled={pending}
        title="Re-read .sdlc/threat-model.yaml from the default branch"
        className="border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:border-accent hover:text-accent disabled:opacity-40"
      >
        sync manifest
      </button>
    </span>
  );
}

function DeclareForm({ repoId }: { repoId: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<string>("asset");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [exposure, setExposure] = useState("unknown");
  const [sensitivity, setSensitivity] = useState("unknown");
  const [selectorInputs, setSelectorInputs] = useState<Partial<Record<SelectorKind, string>>>(
    {},
  );
  const [levels, setLevels] = useState<{ cr: string; ir: string; ar: string }>({
    cr: "",
    ir: "",
    ar: "",
  });
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  async function submit() {
    setError(null);
    const response = await fetch(`/api/repos/${encodeURIComponent(repoId)}/surfaces`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind,
        name,
        description,
        exposure,
        sensitivity,
        selectors: selectorsFromInputs(selectorInputs),
        // Only an asset carries Security Requirements; the backend refuses
        // them anywhere else, so they are not sent.
        ...(kind === "asset"
          ? {
              cr: levels.cr || null,
              ir: levels.ir || null,
              ar: levels.ar || null,
            }
          : {}),
      }),
    });
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { detail?: string } | null;
      setError(body?.detail ?? `The declaration was refused (HTTP ${response.status}).`);
      return;
    }
    setName("");
    setDescription("");
    setSelectorInputs({});
    setLevels({ cr: "", ir: "", ar: "" });
    setOpen(false);
    startTransition(() => router.refresh());
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="self-start border border-rule px-2 py-1 font-mono text-[12px] text-ink-2 hover:border-accent hover:text-accent"
      >
        declare an asset, entry point or boundary
      </button>
    );
  }

  return (
    <div className="flex flex-col gap-2 border border-rule bg-paper-2 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={kind}
          onChange={(event) => setKind(event.target.value)}
          className="border border-rule bg-paper p-1 font-mono text-[12px] text-ink"
        >
          {KINDS.map((entry) => (
            <option key={entry.id} value={entry.id}>
              {entry.label}
            </option>
          ))}
        </select>
        <input
          type="text"
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="name — e.g. Cardholder database"
          className="min-w-[18rem] flex-1 border border-rule bg-paper px-1.5 py-1 font-mono text-[12px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
        />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-1 font-mono text-[11px] text-ink-3">
          exposure
          <select
            value={exposure}
            onChange={(event) => setExposure(event.target.value)}
            className="border border-rule bg-paper p-1 text-[12px] text-ink"
          >
            {EXPOSURES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        {/* Only for an asset. Asking how sensitive a *way in* is produces an
            answer nobody can act on, and the backend drops it regardless. */}
        {kind === "asset" ? (
          <label className="flex items-center gap-1 font-mono text-[11px] text-ink-3">
            holds
            <select
              value={sensitivity}
              onChange={(event) => setSensitivity(event.target.value)}
              className="border border-rule bg-paper p-1 text-[12px] text-ink"
            >
              {SENSITIVITIES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        <input
          type="text"
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          placeholder="what it is, briefly"
          className="min-w-[16rem] flex-1 border border-rule bg-paper px-1.5 py-1 font-mono text-[12px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
        />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {SELECTOR_KINDS.map((selector) => (
          <label
            key={selector}
            className="flex min-w-[14rem] flex-1 items-center gap-1 font-mono text-[11px] text-ink-3"
          >
            {SELECTOR_LABELS[selector]}
            <input
              type="text"
              value={selectorInputs[selector] ?? ""}
              onChange={(event) =>
                setSelectorInputs({ ...selectorInputs, [selector]: event.target.value })
              }
              placeholder={SELECTOR_PLACEHOLDERS[selector]}
              className="flex-1 border border-rule bg-paper px-1.5 py-1 text-[12px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
            />
          </label>
        ))}
      </div>

      {kind === "asset" ? (
        <div className="flex flex-wrap items-center gap-2">
          {(["cr", "ir", "ar"] as const).map((metric) => (
            <label
              key={metric}
              className="flex items-center gap-1 font-mono text-[11px] text-ink-3"
            >
              {metric.toUpperCase()}
              <select
                value={levels[metric]}
                onChange={(event) => setLevels({ ...levels, [metric]: event.target.value })}
                className="border border-rule bg-paper p-1 text-[12px] text-ink"
              >
                {LEVELS.map((value) => (
                  <option key={value} value={value}>
                    {value || "derive"}
                  </option>
                ))}
              </select>
            </label>
          ))}
          <span className="font-mono text-[11px] text-ink-3">
            Leave as <span className="text-ink-2">derive</span> unless you know the
            requirement: it is then taken from what the asset holds.
          </span>
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => void submit()}
          disabled={pending || !name.trim()}
          title={name.trim() ? "Record this declaration" : "A name is required"}
          className="border border-rule px-2 py-0.5 font-mono text-[12px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40"
        >
          declare
        </button>
        <button
          type="button"
          onClick={() => {
            setOpen(false);
            setError(null);
          }}
          className="px-1 font-mono text-[12px] text-ink-3 hover:text-accent"
        >
          cancel
        </button>
        <span className="font-mono text-[11px] text-ink-3">
          Leave exposure as <span className="text-ink-2">unknown</span> if you do
          not know — it is a real answer, and guessing understates risk.
        </span>
      </div>

      {error ? (
        <p className="max-w-prose text-[11px] leading-snug text-critical">{error}</p>
      ) : null}
    </div>
  );
}
