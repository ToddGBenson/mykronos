import Link from "next/link";

import { ErrorPanel, RelativeTime } from "@/components/primitives";
import { getBriefing } from "@/lib/server";
import { getRunSheet } from "@/lib/server-today";
import {
  STATE_META,
  headline,
  watchStep,
  type ItemLike,
  type RunState,
  type StepLike,
} from "@/lib/today";

export const dynamic = "force-dynamic";

export const metadata = { title: "Today — Mykronos" };

/**
 * Today: the run sheet (TheHub #61141, P1 and P6). Read-only.
 *
 * The operator's day in the order it happens: decide, merge, deploy, tasks,
 * watch. It is Start-Here's sections, computed by the server, with a state, a
 * reason and an owner on every line, so "not yet" always says why and whose
 * move it is. There are no buttons on purpose: the actions (#61142) are
 * turned on only after this page has agreed with `Start-Here -Check` for a
 * week.
 */
export default async function TodayPage() {
  const [sheet, briefing] = await Promise.all([getRunSheet(), getBriefing()]);
  if (!sheet.ok) return <ErrorPanel title="Run sheet unavailable" detail={sheet.error} />;

  const watch = briefing.ok
    ? watchStep(briefing.data.stalled ?? [], briefing.data.stale ?? null)
    : watchStep(null, null, briefing.error);
  const steps: StepLike[] = [...sheet.data.steps, watch];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h1 className="text-xl font-bold tracking-tight">Today</h1>
        <span className="font-mono text-[13px] text-ink-2">{headline(steps)}</span>
        <span className="font-mono text-[12px] text-ink-3">
          computed <RelativeTime value={sheet.data.generated_at} /> · read-only
        </span>
      </div>
      <ol className="flex flex-col gap-3">
        {steps.map((s, index) => (
          <StepCard key={s.key} step={s} n={index + 1} />
        ))}
      </ol>
    </div>
  );
}

const TONE_TEXT: Record<string, string> = {
  accent: "text-accent",
  high: "text-high",
  critical: "text-critical",
  pass: "text-pass",
  muted: "text-ink-3",
};

function StateMark({ state }: { state: RunState }) {
  const meta = STATE_META[state];
  return (
    <span
      className={`inline-flex items-center gap-1 whitespace-nowrap font-mono text-[11px] font-bold uppercase tracking-[0.08em] ${TONE_TEXT[meta.tone]}`}
    >
      <span aria-hidden>{meta.icon}</span>
      {meta.word}
    </span>
  );
}

function ItemRow({ item, step }: { item: ItemLike; step: string }) {
  const href =
    step === "decide" && item.ref
      ? `/product-owner/review-queue/${encodeURIComponent(item.ref)}`
      : item.url || "";
  return (
    <li className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 border-t border-rule-soft px-3 py-2">
      <StateMark state={item.state} />
      {href ? (
        href.startsWith("/") ? (
          <Link href={href} className="text-[14px] text-accent underline-offset-2 hover:underline">
            {item.text}
          </Link>
        ) : (
          <a href={href} className="text-[14px] text-accent underline-offset-2 hover:underline">
            {item.text}
          </a>
        )
      ) : (
        <span className="text-[14px]">{item.text}</span>
      )}
      <span className="text-[13px] text-ink-2">{item.reason}</span>
      <span className="ml-auto font-mono text-[12px] text-ink-3">{item.owner}</span>
    </li>
  );
}

function StepCard({ step, n }: { step: StepLike; n: number }) {
  return (
    <li
      aria-labelledby={`step-${step.key}`}
      className={`border bg-paper-2 ${step.state === "ready" ? "border-accent" : "border-rule"}`}
    >
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2">
        <h2 id={`step-${step.key}`} className="text-[15px] font-bold">
          {n} {step.title}
        </h2>
        <span className="text-[13px] text-ink-2">{step.summary}</span>
        <span className="ml-auto">
          <StateMark state={step.state} />
        </span>
      </div>
      {step.reason ? (
        <p
          className={`border-t border-rule-soft px-3 py-1.5 text-[13px] ${
            step.status === "ok" ? "text-ink-2" : "text-high"
          }`}
        >
          {step.status === "ok" ? "" : `${step.status === "partial" ? "Partly read" : "Not read"}: `}
          {step.reason}
        </p>
      ) : null}
      {step.items.length ? (
        <ul>
          {step.items.map((item) => (
            <ItemRow key={`${item.ref}:${item.text}`} item={item} step={step.key} />
          ))}
        </ul>
      ) : null}
      {step.hidden.length || step.notes.length ? (
        <ul className="border-t border-rule-soft px-3 py-1.5 font-mono text-[12px] text-ink-3">
          {step.hidden.map((h) => (
            <li key={h}>hidden: {h}</li>
          ))}
          {step.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}
