import Link from "next/link";

import { DecideDrawerView } from "@/components/decide-drawer";
import { ErrorPanel, RelativeTime } from "@/components/primitives";
import { DeployAction, MergeInOrder } from "@/components/runsheet-actions";
import { pendingRequestIds } from "@/lib/approval-queue";
import { getReviewPacket } from "@/lib/po-console";
import { decideHref, drawerNext, mergeBatch, showActions } from "@/lib/runsheet-actions";
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
 * Today: the run sheet (TheHub #61141, P1 and P6).
 *
 * The operator's day in the order it happens: decide, merge, deploy, tasks,
 * watch. It is Start-Here's sections, computed by the server, with a state, a
 * reason and an owner on every line, so "not yet" always says why and whose
 * move it is.
 *
 * Its actions (#61142: Merge in order, Deploy and the Decide drawer) render
 * only when this server's `MYKRONOS_RUNSHEET_ACTIONS=on` and the backend's
 * `runsheet_actions_enabled` are both on. Both default off (operator decision
 * 2026-11-04), and with either off the page is read-only, exactly as before.
 */
export default async function TodayPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const [sheet, briefing, params] = await Promise.all([
    getRunSheet(),
    getBriefing(),
    searchParams,
  ]);
  if (!sheet.ok) return <ErrorPanel title="Run sheet unavailable" detail={sheet.error} />;
  const actions = showActions(process.env, sheet.data.actions_enabled);
  const decide = actions && typeof params.decide === "string" ? params.decide : "";
  const drawer = decide ? await decideDrawer(decide) : null;

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
          computed <RelativeTime value={sheet.data.generated_at} />
          {actions ? "" : " · read-only"}
        </span>
      </div>
      {drawer}
      <ol className="flex flex-col gap-3">
        {steps.map((s, index) => (
          <StepCard key={s.key} step={s} n={index + 1} actions={actions} />
        ))}
      </ol>
    </div>
  );
}

async function decideDrawer(requestId: string) {
  const [packet, pendingIds] = await Promise.all([
    getReviewPacket(requestId),
    pendingRequestIds(),
  ]);
  if (!packet.ok) return <ErrorPanel title="Review packet unavailable" detail={packet.error} />;
  const next = drawerNext(pendingIds, requestId);
  return <DecideDrawerView packet={packet.data} nextHref={next.href} nextLabel={next.label} />;
}

function StepActions({ step }: { step: StepLike }) {
  if (step.key === "merge") {
    const { batch, left } = mergeBatch(step.items);
    return <MergeInOrder batch={batch} left={left} notes={step.notes} />;
  }
  if (step.key === "deploy" && step.state === "ready") {
    const sha = step.items.find((item) => item.sha)?.sha ?? "";
    return <DeployAction sha={sha} notes={step.notes} />;
  }
  return null;
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

function ItemRow({ item, step, actions }: { item: ItemLike; step: string; actions: boolean }) {
  const href =
    step === "decide" && item.ref
      ? actions
        ? decideHref(item.ref)
        : `/product-owner/review-queue/${encodeURIComponent(item.ref)}`
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

function StepCard({ step, n, actions }: { step: StepLike; n: number; actions: boolean }) {
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
            <ItemRow
              key={`${item.ref}:${item.text}`}
              item={item}
              step={step.key}
              actions={actions}
            />
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
      {actions ? <StepActions step={step} /> : null}
    </li>
  );
}
