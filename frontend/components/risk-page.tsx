/**
 * The Risk page's matrix and age chart (TheHub #61139). The logic is in
 * `lib/risk-page.ts`; this file only draws it.
 *
 * Every state has a colour, an icon and a word, so nothing is told apart by
 * colour alone, and each cell's link carries the state in words as its
 * accessible name. Colours name the v2 palette's tokens (#61135) with today's
 * tokens as the fallback, so the page reads correctly before and after that
 * palette lands.
 */

import Link from "next/link";
import type { CSSProperties, ReactNode } from "react";

import type { AgeBucket, CountCell, RiskPage, StateCell, Tone } from "@/lib/risk-page";

const TONE_COLOUR: Record<Tone, string> = {
  ok: "var(--color-ok, var(--color-pass))",
  fail: "var(--color-fail, var(--color-critical))",
  warn: "var(--color-warn, var(--color-high))",
  stale: "var(--color-stale, var(--color-ink-3))",
  never: "var(--color-ink-3)",
  acc: "var(--color-accepted, var(--color-medium))",
};

const ON_FILL = "var(--color-on-fill, var(--color-paper))";

type Icon = "tick" | "cross" | "clock" | "ring" | "shield" | "triangle";

const TONE_ICON: Record<Tone, Icon> = {
  ok: "tick",
  fail: "cross",
  warn: "triangle",
  stale: "clock",
  never: "ring",
  acc: "shield",
};

function StateIcon({ icon }: { icon: Icon }) {
  const common = {
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 16 16"
      aria-hidden="true"
      data-icon={icon}
      className="shrink-0"
    >
      {icon === "tick" ? <path d="M3 8.5l3.2 3.2L13 5" {...common} /> : null}
      {icon === "cross" ? <path d="M4 4l8 8M12 4l-8 8" {...common} /> : null}
      {icon === "clock" ? (
        <>
          <circle cx="8" cy="8" r="5.6" {...common} strokeWidth={1.8} />
          <path d="M8 5v3.4l2.3 1.4" {...common} strokeWidth={1.8} />
        </>
      ) : null}
      {icon === "ring" ? (
        <circle cx="8" cy="8" r="5.6" {...common} strokeWidth={1.8} strokeDasharray="2.4 2" />
      ) : null}
      {icon === "shield" ? (
        <path d="M8 2.2l5 1.9v3.7c0 3-2.2 5.2-5 6-2.8-.8-5-3-5-6V4.1z" {...common} strokeWidth={1.8} />
      ) : null}
      {icon === "triangle" ? (
        <>
          <path d="M8 2.4l6 10.8H2z" {...common} strokeWidth={1.8} />
          <path d="M8 6.6v3M8 11.4v.2" {...common} strokeWidth={1.8} />
        </>
      ) : null}
    </svg>
  );
}

/** A state pill: filled for evidence, dashed outline for "never". */
export function StatePill({ tone, children }: { tone: Tone; children: ReactNode }) {
  const style: CSSProperties =
    tone === "never"
      ? { border: `1.5px dashed ${TONE_COLOUR.never}`, color: "var(--color-ink-2)" }
      : { background: TONE_COLOUR[tone], color: ON_FILL };
  return (
    <span
      data-tone={tone}
      style={style}
      className="inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-[11.5px] font-semibold"
    >
      <StateIcon icon={TONE_ICON[tone]} />
      {children}
    </span>
  );
}

const LINK = "inline-flex min-h-11 items-center hover:underline focus-visible:outline-2";

function StateLink({ cell, who, what }: { cell: StateCell; who: string; what: string }) {
  return (
    <Link href={cell.href} aria-label={`${who} ${what}: ${cell.label}`} title={cell.label} className={LINK}>
      <StatePill tone={cell.tone}>{cell.text}</StatePill>
    </Link>
  );
}

const COUNT_STYLE: Record<CountCell["tone"], CSSProperties> = {
  crit: { color: "var(--color-critical)" },
  high: { color: "var(--color-high)" },
  med: { color: "var(--color-medium)" },
  warn: { color: TONE_COLOUR.warn },
  zero: { color: "var(--color-ink-3)", fontWeight: 400 },
  unknown: { color: "var(--color-ink-3)", fontWeight: 400 },
};

function CountLink({ cell, who, what }: { cell: CountCell; who: string; what: string }) {
  return (
    <Link
      href={cell.href}
      aria-label={`${who} ${what}: ${cell.label}`}
      title={cell.label}
      data-tone={cell.tone}
      style={COUNT_STYLE[cell.tone]}
      className={`${LINK} min-w-11 justify-end font-mono font-semibold tabular-nums`}
    >
      {cell.value === null ? "?" : cell.value}
    </Link>
  );
}

function NeedsLink({ cell, who }: { cell: CountCell; who: string }) {
  return (
    <Link
      href={cell.href}
      aria-label={`${who} needs you: ${cell.label}`}
      title={cell.label}
      data-tone={cell.tone}
      className="inline-flex min-h-11 min-w-11 items-center justify-center rounded border-[1.5px] border-accent px-2 font-mono text-[12px] font-semibold text-accent hover:bg-accent hover:text-paper"
    >
      {cell.value === null ? "?" : cell.value}
    </Link>
  );
}

const HEADINGS: { label: string; numeric?: boolean }[] = [
  { label: "Product" },
  { label: "Gate (main)" },
  { label: "Prod lag" },
  { label: "Crit", numeric: true },
  { label: "High", numeric: true },
  { label: "Med", numeric: true },
  { label: "Oldest high+ / target" },
  { label: "Overdue", numeric: true },
  { label: "Lanes" },
  { label: "Accepted · expiring" },
  { label: "Needs you", numeric: true },
];

type Cells = RiskPage["estate"];

function RowCells({ cells, who }: { cells: Cells; who: string }) {
  return (
    <>
      <td className="px-2.5">
        <StateLink cell={cells.gate} who={who} what="gate" />
      </td>
      <td className="px-2.5">
        <StateLink cell={cells.lag} who={who} what="prod lag" />
      </td>
      <td className="px-2.5 text-right">
        <CountLink cell={cells.critical} who={who} what="critical" />
      </td>
      <td className="px-2.5 text-right">
        <CountLink cell={cells.high} who={who} what="high" />
      </td>
      <td className="px-2.5 text-right">
        <CountLink cell={cells.medium} who={who} what="medium" />
      </td>
      <td className="px-2.5">
        <StateLink cell={cells.oldest} who={who} what="oldest high or critical" />
      </td>
      <td className="px-2.5 text-right">
        <CountLink cell={cells.overdue} who={who} what="overdue" />
      </td>
      <td className="px-2.5">
        <StateLink cell={cells.lanes} who={who} what="lanes" />
      </td>
      <td className="px-2.5">
        <StateLink cell={cells.accepted} who={who} what="accepted risk" />
      </td>
      <td className="px-2.5 text-right">
        <NeedsLink cell={cells.needs} who={who} />
      </td>
    </>
  );
}

export function RiskMatrix({ page }: { page: RiskPage }) {
  return (
    <div className="scroll-x border border-rule bg-paper-2">
      <table className="w-full min-w-[980px] border-collapse text-[12.5px]">
        <caption className="sr-only">
          Risk by product: gate, production lag, open findings by severity, the oldest high or
          critical against its target, overdue, lanes, accepted risk, and requests waiting on you.
        </caption>
        <thead>
          <tr className="border-b border-rule bg-paper-3 text-left">
            {HEADINGS.map((h) => (
              <th
                key={h.label}
                scope="col"
                className={`whitespace-nowrap px-2.5 py-2 font-mono text-[10.5px] font-semibold uppercase tracking-[0.08em] text-ink-3 ${
                  h.numeric ? "text-right" : ""
                }`}
              >
                {h.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {page.rows.map((row) => (
            <tr key={row.repoId} className="whitespace-nowrap border-b border-rule-soft">
              <th scope="row" className="px-2.5 text-left">
                <Link
                  href={`/repos/${row.repoId}`}
                  className="inline-flex min-h-11 items-center text-[15px] font-semibold text-ink hover:text-accent"
                >
                  {row.name}
                </Link>
                {row.synthetic ? (
                  <span className="ml-2 font-mono text-[11px] text-ink-3">benchmark</span>
                ) : null}
              </th>
              <RowCells cells={row} who={row.name} />
            </tr>
          ))}
          <tr className="whitespace-nowrap bg-paper-3 font-semibold">
            <th scope="row" className="px-2.5 text-left text-ink">
              Estate
            </th>
            <RowCells cells={page.estate} who="Estate" />
          </tr>
        </tbody>
      </table>
    </div>
  );
}

export function AgeChart({ buckets }: { buckets: AgeBucket[] }) {
  const widest = Math.max(1, ...buckets.map((b) => b.total));
  const pct = (n: number) => `${(n / widest) * 100}%`;
  return (
    <section className="flex flex-col gap-2 border border-rule bg-paper-2 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[15px] font-semibold text-ink">Open high and critical, by age</h2>
        <span className="flex items-center gap-3 font-mono text-[11px] text-ink-3">
          <span className="inline-flex items-center gap-1">
            <i className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: "var(--color-critical)" }} />
            critical
          </span>
          <span className="inline-flex items-center gap-1">
            <i className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: "var(--color-high)" }} />
            high
          </span>
        </span>
      </div>
      <ul className="flex flex-col gap-1.5">
        {buckets.map((b) => (
          <li
            key={b.label}
            aria-label={`${b.label}: ${b.critical} critical, ${b.high} high`}
            className="grid grid-cols-[96px_1fr_36px] items-center gap-2.5"
          >
            <span className="text-[12.5px] text-ink-3">{b.label}</span>
            <span className="flex h-3.5 overflow-hidden rounded-sm bg-paper-3" aria-hidden="true">
              <i className="block h-full" style={{ width: pct(b.critical), background: "var(--color-critical)" }} />
              <i className="block h-full" style={{ width: pct(b.high), background: "var(--color-high)" }} />
            </span>
            <b className="text-right font-mono tabular-nums text-ink">{b.total}</b>
          </li>
        ))}
      </ul>
    </section>
  );
}
