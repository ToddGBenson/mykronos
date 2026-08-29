"use client";

/**
 * The off switch (spec 32 §6).
 *
 * Deliberately a *separate* control from `CapabilityManager`, and the
 * separation is the point rather than a layout choice. That component asks
 * "should this repository be scanned for X" — a question answered by a pull
 * request, because it adds or removes code that runs in somebody's
 * repository. This one asks "is the lane that already exists switched on",
 * which is one API call and no review.
 *
 * Folding the two into one button would have made the fast path
 * indistinguishable from the slow one, and would have implied that switching
 * a lane off withdraws the capability. It does not: the grant still permits
 * writes, and the coverage cross-check still expects the capability to
 * report. A paused lane that reads `silent` on the Harness tab is the system
 * working — somebody turned it off and the cross-check noticed.
 *
 * **`disabled_inactivity` is rendered as its own state, not as "off".**
 * GitHub switches a scheduled workflow off after sixty days without a push.
 * That is a coverage gap nobody chose, and it looks identical to a deliberate
 * pause unless the reason is on screen.
 */

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";

import { Label, Section } from "@/components/primitives";
import type { WorkflowState, WorkflowsPage } from "@/lib/api";

/** GitHub's vocabulary, plus our own `not_installed`, with what each one
 *  means for the person reading it. Passed through rather than reduced to a
 *  boolean — see the module comment. */
const STATE_COPY: Record<string, { word: string; tone: string; note: string }> = {
  active: {
    word: "running",
    tone: "text-pass",
    note: "Triggers normally.",
  },
  disabled_manually: {
    word: "paused",
    tone: "text-high",
    note: "Somebody switched this off. The file is still there.",
  },
  disabled_inactivity: {
    word: "auto-paused",
    tone: "text-critical",
    note: "GitHub disabled this scheduled workflow after 60 days with no activity. Nobody chose this.",
  },
  disabled_fork: {
    word: "fork",
    tone: "text-ink-3",
    note: "Disabled because this is a fork.",
  },
  not_installed: {
    word: "not installed",
    tone: "text-ink-3",
    note: "Enabled as a capability, and no workflow file is on the default branch. Installing one is a pull request.",
  },
};

export function WorkflowSwitches({
  repoId,
  page,
}: {
  repoId: string;
  page: WorkflowsPage;
}) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function flip(row: WorkflowState) {
    const action = row.enabled ? "disable" : "enable";
    setBusy(row.capability);
    setError(null);
    try {
      const response = await fetch(
        `/api/repos/${repoId}/workflows/${row.capability}/${action}`,
        { method: "PUT" },
      );
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

  // A repository Mykronos installs no workflows into says so, rather than
  // rendering an empty panel that reads as "nothing is running".
  if (page.unavailable) {
    return (
      <Section title="Workflows">
        <p className="font-mono text-[11px] text-ink-3">{page.unavailable}</p>
      </Section>
    );
  }

  if (page.workflows.length === 0) {
    return (
      <Section title="Workflows">
        <p className="font-mono text-[11px] text-ink-3">
          No capability with a workflow template is enabled here yet.
        </p>
      </Section>
    );
  }

  return (
    <Section title="Workflows">
      <table className="w-full border-collapse text-[11px]">
        <thead>
          <tr className="border-b border-rule text-left">
            <th className="py-1 pr-3 font-normal">
              <Label>capability</Label>
            </th>
            <th className="py-1 pr-3 font-normal">
              <Label>state</Label>
            </th>
            <th className="py-1 pr-3 font-normal">
              <Label>why</Label>
            </th>
            <th className="py-1 font-normal" />
          </tr>
        </thead>
        <tbody>
          {page.workflows.map((row) => {
            const copy = STATE_COPY[row.state] ?? {
              word: row.state,
              tone: "text-ink-3",
              note: "",
            };
            const working = busy === row.capability || isPending;
            return (
              <tr key={row.capability} className="border-b border-rule/50">
                <td className="py-1.5 pr-3 font-mono">{row.capability}</td>
                <td className={`py-1.5 pr-3 font-mono ${copy.tone}`}>{copy.word}</td>
                <td className="py-1.5 pr-3 text-ink-2">{copy.note}</td>
                <td className="py-1.5 text-right">
                  {row.installed ? (
                    <button
                      type="button"
                      onClick={() => void flip(row)}
                      disabled={working}
                      title={
                        row.enabled
                          ? `Stop ${row.workflow_file} now. No pull request; the file stays.`
                          : `Start ${row.workflow_file} again. No pull request.`
                      }
                      className={`border px-1.5 py-0.5 font-mono text-[9px] transition-opacity ${
                        working ? "opacity-40" : ""
                      } ${
                        row.enabled
                          ? "border-rule text-ink-3 hover:border-high hover:text-high"
                          : "border-rule text-ink-3 hover:border-pass hover:text-pass"
                      }`}
                    >
                      {row.enabled ? "disable" : "enable"}
                    </button>
                  ) : (
                    // No switch for a file that is not there. The fix is an
                    // install pull request, and offering a toggle that can
                    // only 404 would send somebody looking for a bug.
                    <span className="font-mono text-[9px] text-ink-3">—</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="mt-1.5 font-mono text-[10px] text-ink-3">
        Switching a workflow off does not withdraw the capability — its grant
        still permits writes, and the coverage cross-check still expects it to
        report.
      </p>
      {error ? <p className="mt-1 font-mono text-[10px] text-high">{error}</p> : null}
    </Section>
  );
}
