"use client";

/**
 * The standard set of checks, as buttons (spec 03 §4, spec 16 §15).
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
 */

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";

import { ALL_CAPABILITIES, CAPABILITY_META } from "@/components/primitives";

export function CapabilityManager({
  repoId,
  enabled,
  pending,
  live,
}: {
  repoId: string;
  enabled: string[];
  pending: string[];
  live: string[];
}) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

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
          const isLive = isOn && live.includes(capability);
          const isPendingInstall = !isOn && pending.includes(capability);
          const working = busy === capability || isPending;
          return (
            <button
              key={capability}
              type="button"
              onClick={() => toggle(capability)}
              disabled={working}
              title={`${meta.label} — click to ${isOn ? "disable" : "enable"}`}
              className={`flex items-center gap-1 border px-2 py-1 font-mono text-[10px] transition-opacity ${
                working ? "opacity-40" : ""
              } ${
                isLive
                  ? "border-accent bg-accent/10 text-ink"
                  : isOn || isPendingInstall
                    ? "border-accent text-ink-2"
                    : "border-rule text-ink-3 hover:border-accent"
              }`}
            >
              <span aria-hidden>{meta.icon}</span>
              {capability}
              {isLive ? (
                <span className="text-[8px] uppercase tracking-wider text-accent">
                  live
                </span>
              ) : isOn ? (
                <span className="text-[8px] uppercase tracking-wider text-ink-3">
                  silent
                </span>
              ) : isPendingInstall ? (
                <span className="text-[8px] uppercase tracking-wider text-ink-3">
                  pending
                </span>
              ) : (
                <span className="text-[8px] uppercase tracking-wider text-ink-3">
                  off
                </span>
              )}
            </button>
          );
        })}
      </div>
      {error ? (
        <p className="font-mono text-[10px] text-high">{error}</p>
      ) : null}
    </div>
  );
}
