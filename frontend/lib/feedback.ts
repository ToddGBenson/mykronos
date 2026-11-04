/**
 * Dashboard feedback, filed as a TheHub story (TheHub #61132).
 *
 * The dialog posts to this server's own route, never to a third party: the
 * Next server attaches the admin token, the backend files the story with the
 * Hub token it holds, and the browser sees neither. There is no GitHub
 * fallback, because the platform's repository is public.
 */

export type FeedbackKind = "bug" | "feature";

/** This server's route; `app/api/feedback/route.ts` forwards it to the backend. */
export const FEEDBACK_ROUTE = "/api/feedback";

export const SUMMARY_MIN = 3;
export const SUMMARY_MAX = 200;
export const DETAIL_MAX = 4_000;

export interface FeedbackDraft {
  kind: FeedbackKind;
  summary: string;
  detail: string;
}

export const BLANK_DRAFT: FeedbackDraft = { kind: "bug", summary: "", detail: "" };

export const KIND_LABEL: Record<FeedbackKind, string> = {
  bug: "Something is wrong",
  feature: "I want something",
};

/** Where the dialog is, from opening it to the story being filed. */
export type FeedbackPhase =
  | { kind: "checking" }
  | { kind: "unavailable"; reason: string }
  | { kind: "ready" }
  | { kind: "sending" }
  | { kind: "filed"; storyId: number | null }
  | { kind: "failed"; message: string };

export interface FeedbackStatus {
  available: boolean;
  reason: string | null;
}

/** What is wrong with a draft, or null when it can be sent. The backend holds the same limits. */
export function draftProblem(draft: FeedbackDraft): string | null {
  const summary = draft.summary.trim();
  if (summary.length < SUMMARY_MIN) return `Write a summary of at least ${SUMMARY_MIN} characters.`;
  if (summary.length > SUMMARY_MAX) return `Keep the summary to ${SUMMARY_MAX} characters.`;
  if (draft.detail.length > DETAIL_MAX) {
    return `Keep the detail to ${DETAIL_MAX.toLocaleString("en-US")} characters.`;
  }
  return null;
}

/** The request body: the draft, the page it was written on and the release. Nothing else. */
export function feedbackBody(draft: FeedbackDraft, page: string, release: string) {
  return {
    kind: draft.kind,
    summary: draft.summary.trim(),
    detail: draft.detail.trim(),
    page,
    release,
  };
}

/** The phase a status read puts the dialog in. */
export function phaseFromStatus(status: FeedbackStatus): FeedbackPhase {
  return status.available
    ? { kind: "ready" }
    : { kind: "unavailable", reason: status.reason ?? "TheHub is not connected." };
}
