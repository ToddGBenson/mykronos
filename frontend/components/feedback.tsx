"use client";

/**
 * Report a bug, or ask for something (TheHub #61132).
 *
 * **Filed to TheHub, never to GitHub.** This used to open a pre-filled issue
 * on the platform's own repository, which is public: a report about an
 * internal path or hostname was one click from being published. The dialog
 * now posts to this server's `/api/feedback`, which forwards it with the
 * admin token; the backend files a TheHub story with the Hub token it holds.
 * The browser holds neither token.
 *
 * With no Hub configured the dialog says feedback is unavailable and offers
 * nothing else. A GitHub fallback would reopen the leak this closes.
 *
 * The page and the release are attached because they are the details people
 * forget and maintainers need.
 */

import { usePathname } from "next/navigation";
import { useEffect, useRef, useState, type FormEvent } from "react";

import {
  BLANK_DRAFT,
  DETAIL_MAX,
  FEEDBACK_ROUTE,
  KIND_LABEL,
  SUMMARY_MAX,
  draftProblem,
  feedbackBody,
  phaseFromStatus,
  type FeedbackDraft,
  type FeedbackKind,
  type FeedbackPhase,
  type FeedbackStatus,
} from "@/lib/feedback";

const TITLE_ID = "feedback-title";
const field =
  "w-full border border-rule bg-paper px-2 py-1 font-mono text-[13px] text-ink outline-none focus:border-accent";

export function FeedbackView({
  open,
  phase,
  draft,
  onChange,
  onSubmit,
  onClose,
}: {
  open: boolean;
  phase: FeedbackPhase;
  draft: FeedbackDraft;
  onChange: (draft: FeedbackDraft) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onClose: () => void;
}) {
  if (!open) return null;

  const showForm = phase.kind === "ready" || phase.kind === "sending" || phase.kind === "failed";

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-ink/40 px-4 pt-[10vh]"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={TITLE_ID}
        className="w-full max-w-lg border border-rule bg-paper-2 shadow-lg"
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            event.preventDefault();
            onClose();
          }
        }}
      >
        <div className="flex items-baseline justify-between border-b border-rule px-3 py-2">
          <h2 id={TITLE_ID} className="font-mono text-[13px] font-bold tracking-[0.08em] text-ink">
            Feedback
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="tap font-mono text-[11px] lowercase tracking-[0.08em] text-ink-3 hover:text-accent"
          >
            close · esc
          </button>
        </div>

        {phase.kind === "checking" ? (
          <p role="status" className="px-3 py-3 text-[14px] text-ink-3">
            Checking whether feedback can be filed…
          </p>
        ) : null}

        {phase.kind === "unavailable" ? (
          <div role="status" className="flex flex-col gap-1 px-3 py-3 text-[14px]">
            <p className="font-bold text-ink">Feedback is unavailable.</p>
            <p className="text-ink-2">{phase.reason}</p>
          </div>
        ) : null}

        {phase.kind === "filed" ? (
          <p role="status" className="px-3 py-3 text-[14px] text-ink">
            {phase.storyId === null
              ? "Filed on TheHub."
              : `Filed as TheHub story #${phase.storyId}.`}
          </p>
        ) : null}

        {showForm ? (
          <form onSubmit={onSubmit} className="flex flex-col gap-3 px-3 py-3">
            <fieldset className="flex flex-wrap gap-4">
              <legend className="sr-only">Kind</legend>
              {(["bug", "feature"] as FeedbackKind[]).map((kind) => (
                <label key={kind} className="inline-flex items-center gap-1.5 text-[14px] text-ink">
                  <input
                    type="radio"
                    name="feedback-kind"
                    value={kind}
                    checked={draft.kind === kind}
                    onChange={() => onChange({ ...draft, kind })}
                  />
                  {KIND_LABEL[kind]}
                </label>
              ))}
            </fieldset>
            <div className="flex flex-col gap-1">
              <label htmlFor="feedback-summary" className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
                Summary
              </label>
              <input
                id="feedback-summary"
                type="text"
                required
                maxLength={SUMMARY_MAX}
                value={draft.summary}
                onChange={(event) => onChange({ ...draft, summary: event.target.value })}
                className={field}
              />
            </div>
            <div className="flex flex-col gap-1">
              <label htmlFor="feedback-detail" className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
                What happened, or what would help
              </label>
              <textarea
                id="feedback-detail"
                maxLength={DETAIL_MAX}
                value={draft.detail}
                onChange={(event) => onChange({ ...draft, detail: event.target.value })}
                className={`${field} min-h-28`}
              />
            </div>
            <p className="text-[12px] text-ink-3">
              Filed as a private TheHub story, with this page and release attached.
            </p>
            {phase.kind === "failed" ? (
              <p role="alert" className="text-[13px] text-critical">
                {phase.message}
              </p>
            ) : null}
            <div>
              <button
                type="submit"
                disabled={phase.kind === "sending"}
                className="border border-accent px-3 py-1 font-mono text-[13px] text-accent hover:bg-paper-3 disabled:opacity-50"
              >
                {phase.kind === "sending" ? "Filing…" : "File it"}
              </button>
            </div>
          </form>
        ) : null}
      </div>
    </div>
  );
}

export function Feedback() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [phase, setPhase] = useState<FeedbackPhase>({ kind: "checking" });
  const [draft, setDraft] = useState<FeedbackDraft>(BLANK_DRAFT);
  const trigger = useRef<HTMLButtonElement | null>(null);

  // Asked each time the dialog opens, so it says "unavailable" before anything is typed.
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    fetch(FEEDBACK_ROUTE, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) {
          setPhase({ kind: "unavailable", reason: `The server could not say (HTTP ${response.status}).` });
          return;
        }
        setPhase(phaseFromStatus((await response.json()) as FeedbackStatus));
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setPhase({ kind: "unavailable", reason: "The server could not be reached." });
        }
      });
    return () => controller.abort();
  }, [open]);

  // Focus the first field once the form shows.
  useEffect(() => {
    if (open && phase.kind === "ready") document.getElementById("feedback-summary")?.focus();
  }, [open, phase.kind]);

  function close() {
    setOpen(false);
    if (phase.kind === "filed") setDraft(BLANK_DRAFT);
    trigger.current?.focus();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const problem = draftProblem(draft);
    if (problem) {
      setPhase({ kind: "failed", message: problem });
      return;
    }
    setPhase({ kind: "sending" });
    try {
      const response = await fetch(FEEDBACK_ROUTE, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          feedbackBody(draft, pathname, process.env.NEXT_PUBLIC_VERSION ?? "0.1.0"),
        ),
      });
      const body = (await response.json().catch(() => ({}))) as {
        story_id?: number | null;
        detail?: unknown;
      };
      if (response.status === 503) {
        setPhase({
          kind: "unavailable",
          reason: typeof body.detail === "string" ? body.detail : "TheHub is not connected.",
        });
        return;
      }
      if (!response.ok) {
        setPhase({
          kind: "failed",
          message:
            typeof body.detail === "string"
              ? body.detail
              : `The report was not filed (HTTP ${response.status}).`,
        });
        return;
      }
      setPhase({ kind: "filed", storyId: body.story_id ?? null });
    } catch {
      setPhase({ kind: "failed", message: "The server could not be reached. Nothing was filed." });
    }
  }

  return (
    <>
      <button
        ref={trigger}
        type="button"
        onClick={() => {
          setPhase({ kind: "checking" });
          setOpen(true);
        }}
        aria-haspopup="dialog"
        title="Report a bug or ask for something. It is filed as a private TheHub story."
        className="tap whitespace-nowrap border border-rule px-1.5 py-0.5 font-mono text-[11px] lowercase tracking-[0.08em] text-ink-3 hover:border-accent hover:text-accent"
      >
        feedback
      </button>
      <FeedbackView
        open={open}
        phase={phase}
        draft={draft}
        onChange={setDraft}
        onSubmit={submit}
        onClose={close}
      />
    </>
  );
}
