/**
 * The morning briefing page's reasoning (TheHub #60864): what each section
 * status says, how lines group by the work they become, and where a line's
 * `ref` leads.
 *
 * Kept out of the component so it can be tested without rendering, and so
 * the page renders whatever the API returns. B3 (TheHub #60861) fills
 * "Needs you today" and "Sprint health" with board stories and pull
 * requests; nothing here changes when it merges.
 */

import type { components } from "./api-types";

export type DailyBriefing = components["schemas"]["DailyBriefingOut"];
export type BriefingSection = components["schemas"]["BriefingSectionOut"];
export type BriefingLine = components["schemas"]["BriefingLineOut"];
export type SectionStatus = BriefingSection["status"];
export type WorkKind = BriefingLine["work"];

/** A product the switcher offers: an onboarding id and its repository. */
export type BriefingProduct = { repoId: string; repoFullName: string };

/** The order work is shown in: what can land today first. */
export const WORK_ORDER: WorkKind[] = ["merge", "decision", "story"];

export const WORK_LABEL: Record<WorkKind, string> = {
  merge: "Merge",
  decision: "Decision",
  story: "Story",
};

export const STATUS_META: Record<
  SectionStatus,
  { tone: "pass" | "warn" | "critical" | "muted"; word: string; meaning: string }
> = {
  ok: { tone: "pass", word: "Read", meaning: "Every source this section needs was read." },
  partial: {
    tone: "warn",
    word: "Partial",
    meaning: "Some of its sources were read; the reason names the ones that were not.",
  },
  unavailable: {
    tone: "critical",
    word: "Unavailable",
    meaning:
      "Its source could not be read. This is not an all-clear: nothing here was checked.",
  },
  not_available: {
    tone: "muted",
    word: "Not built yet",
    meaning: "This section's source is not wired up yet. Empty on purpose, not invented.",
  },
};

/** A status the API may add later still renders, as muted, with its own word. */
export function statusMeta(status: string) {
  return (
    STATUS_META[status as SectionStatus] ?? {
      tone: "muted" as const,
      word: status,
      meaning: "",
    }
  );
}

/** Lines grouped by the work they become, in `WORK_ORDER`, empty groups dropped. */
export function groupByWork(
  lines: BriefingLine[] | undefined,
): { work: WorkKind; lines: BriefingLine[] }[] {
  const all = lines ?? [];
  return WORK_ORDER.map((work) => ({
    work,
    lines: all.filter((line) => line.work === work),
  })).filter((group) => group.lines.length > 0);
}

/** Counts of each kind of work across sections, each line once, the focus list left out. */
export function workCounts(sections: BriefingSection[]): Record<WorkKind, number> {
  const counts: Record<WorkKind, number> = { merge: 0, decision: 0, story: 0 };
  const seen = new Set<string>();
  for (const section of sections) {
    if (section.key === "suggested_focus") continue;
    for (const line of section.lines ?? []) {
      const identity = `${line.what}\u0000${line.ref}\u0000${line.repo_full_name}`;
      if (seen.has(identity)) continue;
      seen.add(identity);
      counts[line.work] += 1;
    }
  }
  return counts;
}

export type RefLink = { href: string; label: string; external: boolean };

const STORY_REF = /^TheHub #(\d+)$/;
const ACCEPTANCE_REF = /^\/api\/risk-acceptances\/([^/]+)$/;
const SCAN_RUN_REF = /^\/api\/dashboard\/scan-runs\/([^/]+)$/;

/**
 * Where a line's `ref` leads, or null when it names nothing a page shows.
 *
 * The API's refs are what each section had to hand: a pull request or build
 * URL, a board story ("TheHub #60864"), an API route for an acceptance or a
 * scan run, a finding id, a fix id. Each maps to the dashboard page for it.
 * An API route with no page (`/api/exposure`) is shown as text, not as a link
 * to JSON.
 */
export function refLink(
  ref: string,
  repoFullName: string,
  repoIds: Record<string, string>,
): RefLink | null {
  const value = ref.trim();
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) {
    const pull = value.match(/\/pull\/(\d+)/);
    return { href: value, label: pull ? `PR #${pull[1]}` : "open", external: true };
  }
  const story = value.match(STORY_REF);
  if (story) {
    // TheHub's board is read here through the Product Owner page.
    return { href: "/product-owner", label: `TheHub #${story[1]}`, external: false };
  }
  const repoId = repoFullName ? repoIds[repoFullName] : undefined;
  const acceptance = value.match(ACCEPTANCE_REF);
  if (acceptance) {
    return repoId
      ? {
          href: `/repos/${encodeURIComponent(repoId)}/risk/${encodeURIComponent(acceptance[1])}`,
          label: "acceptance",
          external: false,
        }
      : { href: "/decisions", label: "acceptance", external: false };
  }
  const scanRun = value.match(SCAN_RUN_REF);
  if (scanRun && repoId) {
    return {
      href: `/repos/${encodeURIComponent(repoId)}/scan-runs/${encodeURIComponent(scanRun[1])}`,
      label: "scan run",
      external: false,
    };
  }
  if (value.startsWith("/")) return null;
  // A fix group's id is `<kind>:<target>` (`upgrade:lodash@4.17.21`,
  // guidance.py); the remediation worklist is where fixes are worked.
  if (/^[a-z_]+:\S/.test(value) || value.startsWith("fix-")) {
    return { href: "/remediate", label: "fix", external: false };
  }
  if (repoId && /^[A-Za-z0-9_-]+$/.test(value)) {
    return {
      href: `/repos/${encodeURIComponent(repoId)}/findings/${encodeURIComponent(value)}`,
      label: "finding",
      external: false,
    };
  }
  return null;
}

/** The repository page for a line, when the repository is onboarded. */
export function repoHref(
  repoFullName: string,
  repoIds: Record<string, string>,
): string | null {
  const repoId = repoFullName ? repoIds[repoFullName] : undefined;
  return repoId ? `/repos/${encodeURIComponent(repoId)}` : null;
}

/** `/briefing`, or one product's briefing. */
export function briefingHref(repoId?: string | null): string {
  return repoId ? `/briefing?repo_id=${encodeURIComponent(repoId)}` : "/briefing";
}

/**
 * What an operator action's probe read from GitHub (TheHub #60972). Empty on
 * every line that is not an operator action.
 */
export type Verification = "observed_done" | "observed_not_done" | "unprobed" | "probe_error";

export const VERIFICATION_META: Record<
  Verification,
  { tone: "pass" | "warn" | "critical" | "muted"; word: string; meaning: string }
> = {
  observed_done: {
    tone: "pass",
    word: "Observed done",
    meaning: "GitHub was read and the ask is in place. Close the story.",
  },
  observed_not_done: {
    tone: "warn",
    word: "Not done yet",
    meaning: "GitHub was read and the ask is not in place.",
  },
  unprobed: {
    tone: "muted",
    word: "Not checked",
    meaning: "No probe is registered for this action, so nothing was checked.",
  },
  probe_error: {
    tone: "critical",
    word: "Could not check",
    meaning: "A probe is registered but could not read GitHub. Never counted as done.",
  },
};

/** A line's verification badge, or null for a line that is not an operator action. */
export function verificationMeta(value: string | undefined | null) {
  if (!value) return null;
  return VERIFICATION_META[value as Verification] ?? VERIFICATION_META.probe_error;
}

/** One operator action as `data.board.operator_actions` carries it. */
export type OperatorAction = {
  id: number | string;
  title: string;
  verification: Verification;
  evidence: string;
};

/**
 * The operator actions a "Needs you today" section carries in its data.
 * An unknown verification reads as `probe_error`, never as done.
 */
export function operatorActions(section: BriefingSection): OperatorAction[] {
  const board = (section.data as Record<string, unknown> | undefined)?.board;
  const raw = (board as Record<string, unknown> | undefined)?.operator_actions;
  if (!Array.isArray(raw)) return [];
  const out: OperatorAction[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const a = item as Record<string, unknown>;
    if (typeof a.title !== "string") continue;
    if (typeof a.id !== "number" && typeof a.id !== "string") continue;
    const verification =
      typeof a.verification === "string" && a.verification in VERIFICATION_META
        ? (a.verification as Verification)
        : a.verification === undefined
          ? "unprobed"
          : "probe_error";
    out.push({
      id: a.id,
      title: a.title,
      verification,
      evidence: typeof a.evidence === "string" ? a.evidence : "",
    });
  }
  return out;
}

/** The actions GitHub shows as done: "Done - close it", not counted as needing you. */
export function doneActions(section: BriefingSection): OperatorAction[] {
  return operatorActions(section).filter((a) => a.verification === "observed_done");
}

/** One product signal (TheHub #60863): measured, not measurable yet, or unread. */
export type ProductSignal = {
  key: string;
  label: string;
  status: "measured" | "not_measurable" | "unavailable";
  source: string;
  value: string;
  reason: string;
};

export const SIGNAL_WORD: Record<ProductSignal["status"], string> = {
  measured: "Measured",
  not_measurable: "Not measurable yet",
  unavailable: "Not read",
};

/**
 * A section's `data.signals`, when it carries them (the per-product
 * "Product signals" block). Anything that is not a well-formed signal is
 * dropped rather than rendered half-empty; an unknown status reads as
 * unavailable, never as measured.
 */
export function productSignals(section: BriefingSection): ProductSignal[] {
  const raw = (section.data as Record<string, unknown> | undefined)?.signals;
  if (!Array.isArray(raw)) return [];
  const out: ProductSignal[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const s = item as Record<string, unknown>;
    if (typeof s.key !== "string" || typeof s.label !== "string") continue;
    const status =
      s.status === "measured" || s.status === "not_measurable" ? s.status : "unavailable";
    out.push({
      key: s.key,
      label: s.label,
      status,
      source: typeof s.source === "string" ? s.source : "",
      value: typeof s.value === "string" ? s.value : "",
      reason: typeof s.reason === "string" ? s.reason : "",
    });
  }
  return out;
}
