"use client";

/**
 * The standard set of checks, as buttons (spec 03 §4, spec 16 §15, spec 17 §2).
 *
 * Every repository is measured against the same fifteen capabilities; this
 * renders each as a toggle. A click sends the whole new set to the backend,
 * which validates it and — for Concourse-scanned repos — syncs the ingestion
 * grants immediately, so the next pipeline run reports. For Actions-scanned
 * repos the same click opens the workflow-install PR, and the capability
 * shows as pending until it merges.
 *
 * Enabling a capability is a claim the pipeline has to honour: a lane that
 * never uploads shows as "enabled, not yet reporting" on the coverage view
 * rather than silently counting as covered.
 *
 * **Colour is run health, not a second finding-severity indicator** (spec 17
 * §2.2). A button is green because its last run succeeded, or because it is
 * an event-driven capability (Aegis/Oracle/Patchwork) that is simply on — not
 * because the repository is clean. It is red because the capability is
 * enabled and not answering (no job produces it, or it has never reported),
 * which is a statement about the pipeline, not about what it has found. This
 * reuses `stageTone`/`stageState` from `pipelines.tsx` rather than a second
 * mapping of the same `CiStage` states, on the same reasoning the toxic-combo
 * rules give for one rule set: two descriptions of the same fact are two
 * things to keep in step, and the one nobody is looking at is the one that
 * drifts.
 */

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";

import {
  ALL_CAPABILITIES,
  CAPABILITY_META,
  INDICATOR,
  type IndicatorTone,
} from "@/components/primitives";
import { stageState, stageTone } from "@/components/pipelines";
import type { CiPage } from "@/lib/api";

/** The button's fill/border for each tone — same colour tokens `IndicatorLight`
 *  draws its lamp from (`INDICATOR`), composed for a filled button instead of
 *  a dot-plus-word, because the two widgets are different shapes for the same
 *  five facts. */
const TONE_BUTTON: Record<IndicatorTone, string> = {
  ok: "border-pass bg-pass/10 text-pass",
  bad: "border-critical bg-critical/10 text-critical",
  warn: "border-high bg-high/10 text-high",
  idle: "border-ink-3 text-ink-2",
  off: "border-rule text-ink-3 hover:border-accent",
};

export function CapabilityManager({
  repoId,
  enabled,
  pending,
  live,
  ci,
}: {
  repoId: string;
  enabled: string[];
  pending: string[];
  live: string[];
  /** The same CI page the Harness tab renders, so a button's colour and the
   *  panel explaining it never disagree. Null when the fetch failed or
   *  hasn't run yet — every capability falls back to the pre-CI heuristic
   *  below rather than the whole control going blank. */
  ci: CiPage | null;
}) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [explaining, setExplaining] = useState<string | null>(null);

  const stagesByCapability = new Map((ci?.stages ?? []).map((s) => [s.stage, s]));

  async function toggle(capability: string) {
    const current = new Set(enabled);
    if (current.has(capability)) {
      current.delete(capability);
    } else {
      current.add(capability);
    }
    setBusy(capability);
    setError(null);
    try {
      const response = await fetch(`/api/repos/${repoId}/capabilities`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ capabilities: [...current].sort() }),
      });
      if (!response.ok) {
        const detail = await response.json().catch(() => null);
        setError(
          typeof detail?.detail === "string"
            ? detail.detail
            : `The change was refused (HTTP ${response.status}).`,
        );
        return;
      }
      startTransition(() => router.refresh());
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-1">
        {ALL_CAPABILITIES.map((capability) => {
          const meta = CAPABILITY_META[capability];
          const isOn = enabled.includes(capability);
          const isPendingInstall = !isOn && pending.includes(capability);
          const stage = stagesByCapability.get(capability);
          const working = busy === capability || isPending;

          // Pending-install is its own state (an install PR not yet merged,
          // spec 10 §7) — not one of the five run-health tones, since nothing
          // has run yet to have a colour about.
          const tone: IndicatorTone | null = isPendingInstall
            ? null
            : !isOn
              ? "off"
              : stage
                ? stageTone(stage)
                : // ci fetch failed or hasn't resolved: fall back to the
                  // scan-health-derived `live` list rather than blanking the
                  // whole control.
                  live.includes(capability)
                  ? "ok"
                  : "idle";
          const word = isPendingInstall ? "pending" : stage ? stageState(stage) : tone;
          const isExplaining = explaining === capability;

          return (
            <button
              key={capability}
              type="button"
              onClick={() =>
                tone === "bad"
                  ? setExplaining(isExplaining ? null : capability)
                  : toggle(capability)
              }
              disabled={working}
              title={
                tone === "bad"
                  ? `${meta.label} — enabled and not answering. Click to see why.`
                  : `${meta.label} — click to ${isOn ? "disable" : "enable"}${
                      "note" in meta ? `. ${meta.note}` : ""
                    }`
              }
              className={`flex items-center gap-1 border px-2 py-1 font-mono text-[10px] transition-opacity ${
                working ? "opacity-40" : ""
              } ${
                isPendingInstall
                  ? "border-accent text-ink-2"
                  : TONE_BUTTON[tone as IndicatorTone]
              }`}
            >
              <span aria-hidden>{meta.icon}</span>
              {capability}
              <span
                className={`text-[8px] uppercase tracking-wider ${
                  tone ? INDICATOR[tone].word : "text-ink-3"
                }`}
              >
                {word}
              </span>
            </button>
          );
        })}
      </div>

      {explaining ? (
        <ExplainRedCapability
          capability={explaining}
          stage={stagesByCapability.get(explaining)}
          onDisableAnyway={() => {
            setExplaining(null);
            void toggle(explaining);
          }}
        />
      ) : null}
      {error ? (
        <p className="font-mono text-[10px] text-high">{error}</p>
      ) : null}
    </div>
  );
}

/**
 * Why a red button is red, and a deliberate second step before disabling it.
 *
 * Spec 17 §2.2: the first useful action on an enabled-but-silent capability
 * is reading why, not silencing it — disabling it makes the red go away
 * without the pipeline getting any healthier.
 */
const RED_REASON: Record<string, string> = {
  no_job: "This repository is enabled for it, and nothing in the pipeline produces it — the repository believes it is covered and no job disagrees, because no job exists.",
  never_reported: "The job runs and has never uploaded a scan to the lake.",
};

function ExplainRedCapability({
  capability,
  stage,
  onDisableAnyway,
}: {
  capability: string;
  stage: { state: string } | undefined;
  onDisableAnyway: () => void;
}) {
  const meta = CAPABILITY_META[capability as keyof typeof CAPABILITY_META];
  const reason =
    (stage && RED_REASON[stage.state]) ??
    "Enabled, and not answering — check the Enabled jobs section on the Harness tab for detail.";
  return (
    <div className="border-l-2 border-critical bg-critical-wash px-3 py-2 text-[11px] text-ink-2">
      <p>
        <strong className="text-critical">{meta?.label ?? capability}</strong>{" "}
        {reason}
      </p>
      <button
        type="button"
        onClick={onDisableAnyway}
        className="mt-1.5 border border-rule px-1.5 py-0.5 font-mono text-[9px] text-ink-3 hover:border-critical hover:text-critical"
      >
        disable anyway
      </button>
    </div>
  );
}
