/**
 * Shared display primitives.
 *
 * Everything here encodes state in *form* as well as number — a pill, a
 * stripe, a dot row — so a 200-row table can be scanned rather than read.
 */

import Link from "next/link";
import type { ReactNode } from "react";

import { SEVERITY_ORDER, type Severity } from "@/lib/api";

// Re-exported so callers have one import for display primitives, even
// though this one has to be a client component.
export { RelativeTime } from "./relative-time";

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  info: "text-info",
};

const SEVERITY_BG: Record<Severity, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-rule",
  info: "bg-rule-soft",
};

export function Mono({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`font-mono ${className}`}>{children}</span>;
}

/**
 * A small uppercase label.
 *
 * `as="h2"` exists because most of these *are* section titles, and an audit
 * found the portfolio page shipping exactly one heading for the whole page —
 * every section styled like a heading and marked up as a span. That leaves a
 * screen-reader user with no outline to navigate by, and it removes the one
 * check that forces a decision about which of these labels is genuinely a
 * section and which is only a caption. A stat tile's label is a caption; "open
 * findings by age" is a section.
 */
export function Label({
  children,
  as,
}: {
  children: ReactNode;
  as?: "h2" | "h3";
}) {
  const className = "font-mono text-[12px] uppercase tracking-[0.12em] text-ink-3";
  if (as === "h2") return <h2 className={className}>{children}</h2>;
  if (as === "h3") return <h3 className={className}>{children}</h3>;
  return <span className={className}>{children}</span>;
}

/**
 * The proportional make-up of a repo's findings, at a glance.
 *
 * Deliberately not a number: two repos with 40 findings each are very
 * different if one is all criticals, and a bar shows that before you read
 * anything.
 */
export function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
  if (total === 0) {
    return (
      <div
        className="h-2.5 w-24 border border-rule bg-paper-2"
        aria-label="No open findings"
      />
    );
  }
  return (
    <div
      className="flex h-2.5 w-24 overflow-hidden border border-rule"
      role="img"
      aria-label={SEVERITY_ORDER.filter((s) => counts[s])
        .map((s) => `${counts[s]} ${s}`)
        .join(", ")}
    >
      {SEVERITY_ORDER.map((severity) =>
        counts[severity] ? (
          <div
            key={severity}
            className={SEVERITY_BG[severity]}
            style={{ width: `${((counts[severity] ?? 0) / total) * 100}%` }}
          />
        ) : null,
      )}
    </div>
  );
}

export function SeverityText({ severity }: { severity: Severity }) {
  return (
    <span
      className={`font-mono text-[12px] font-bold uppercase tracking-[0.08em] ${SEVERITY_CLASS[severity]}`}
    >
      {severity}
    </span>
  );
}

type PillTone = "critical" | "warn" | "pass" | "muted" | "accent";

const PILL: Record<PillTone, string> = {
  critical: "text-critical border-critical bg-critical-wash",
  warn: "text-high border-high bg-high-wash",
  pass: "text-pass border-pass bg-pass-wash",
  muted: "text-ink-3 border-rule",
  accent: "text-accent border-accent bg-accent-wash",
};

export function Pill({
  tone,
  children,
  title,
}: {
  tone: PillTone;
  children: ReactNode;
  /** Hover text. A tone-coded pill carries meaning in its colour, and a
   *  reader who cannot see colour needs somewhere to read it. */
  title?: string;
}) {
  return (
    <span
      title={title}
      className={`inline-block whitespace-nowrap border px-1.5 py-0.5 font-mono text-[11px] font-bold uppercase tracking-[0.08em] ${PILL[tone]}`}
    >
      {children}
    </span>
  );
}

/**
 * The standard set: fifteen checks every repository is measured against, in
 * pipeline-stage order (ALL_STAGES in backend/mykronos/ci.py), so the
 * portfolio column and the repo's CI page read the same way. One icon per
 * capability, used identically everywhere — an icon that changes meaning
 * between pages is worse than no icon.
 */
export const CAPABILITY_META = {
  unit: { icon: "🧪", abbr: "UNIT", label: "Unit tests" },
  qa: { icon: "📋", abbr: "QA", label: "QA / docs quality" },
  sast: { icon: "🔍", abbr: "SAST", label: "Static analysis (SAST)" },
  secrets: { icon: "🔑", abbr: "SEC", label: "Secret scanning" },
  atlas: { icon: "📦", abbr: "SCA", label: "Dependencies (SCA)" },
  containers: { icon: "🐳", abbr: "IMG", label: "Container scanning" },
  iac: { icon: "🏗️", abbr: "IAC", label: "Infrastructure as code" },
  functional: { icon: "🧭", abbr: "FN", label: "Functional tests" },
  dast: { icon: "🕷️", abbr: "DAST", label: "Dynamic analysis (DAST)" },
  cloud: { icon: "☁️", abbr: "CLD", label: "Cloud posture" },
  // No scanner exists behind this one (spec 14 §0, B-007). Enabling it is
  // still meaningful — nmap/nuclei output produced elsewhere ingests normally
  // — but the platform will not run the scan, and a bare "Network scanning"
  // label says the opposite.
  network: {
    icon: "🌐",
    abbr: "NET",
    label: "Network scanning",
    note: "Ingest only — Mykronos does not run network scans yet.",
  },
  ai: { icon: "✨", abbr: "AI", label: "AI checks" },
  aegis: { icon: "🛡️", abbr: "INS", label: "Insider risk" },
  oracle: { icon: "⚖️", abbr: "ORC", label: "Risk decisions" },
  patchwork: { icon: "🩹", abbr: "FIX", label: "Auto-remediation" },
} as const;

export const ALL_CAPABILITIES = Object.keys(
  CAPABILITY_META,
) as (keyof typeof CAPABILITY_META)[];

/**
 * Fleet coverage, as a labelled grid rather than a row of emoji.
 *
 * **What this replaces and why.** The same fifteen slots used to render as
 * fifteen unlabelled emoji at 11px, with state carried by `opacity` and the
 * meaning of each glyph available only by hovering it one at a time. Reading
 * the coverage of four repositories took sixty hover actions and required
 * holding fifteen emoji-to-capability mappings in your head to compare two
 * rows. Screen readers got the Unicode names — "test tube, clipboard,
 * magnifying glass tilted left" — because `title` on a span is not reliably
 * announced and there was no `aria-label`. The 130-word "reading this table"
 * paragraph underneath existed almost entirely to decode this column, which is
 * the tell: a display that needs a paragraph is not finished.
 *
 * Three things changed. The header carries the names, so they are read once
 * rather than hovered sixty times. State is carried by fill *and* border
 * style, so it survives greyscale, low vision, and both themes — opacity alone
 * failed all three, and worst in the light theme. And every cell names itself
 * to assistive technology.
 *
 * The columns are fixed-width and the header uses the same width and gap, so
 * the two line up without a table or a measurement.
 */
const CAP_CELL = "w-[30px] shrink-0";

export function CapabilityGridHeader() {
  return (
    <span className="inline-flex items-end gap-[2px]" aria-hidden>
      {ALL_CAPABILITIES.map((capability) => (
        <span
          key={capability}
          title={CAPABILITY_META[capability].label}
          className={`${CAP_CELL} text-center font-mono text-[10px] leading-none tracking-[0.04em] text-ink-3`}
        >
          {CAPABILITY_META[capability].abbr}
        </span>
      ))}
    </span>
  );
}

export function CapabilityGrid({
  enabled,
  pending = [],
  live = [],
}: {
  enabled: string[];
  pending?: string[];
  /**
   * Capabilities that have actually reported a scan. Implemented-but-silent
   * and implemented-and-reporting are different facts: the first is drawn as
   * an outline, the second as a solid. Without the distinction, "enabled"
   * quietly claims coverage that may not exist — the unit lane was enabled and
   * had never reported once.
   */
  live?: string[];
}) {
  return (
    <span className="inline-flex items-center gap-[2px]">
      {ALL_CAPABILITIES.map((capability) => {
        const meta = CAPABILITY_META[capability];
        const isOn = enabled.includes(capability);
        const isLive = isOn && live.includes(capability);
        const isPending = !isOn && pending.includes(capability);

        const state = isLive
          ? "reporting"
          : isOn
            ? "enabled, not yet reporting"
            : isPending
              ? "pending install PR"
              : "not enabled";

        // Fill for evidence, outline for a claim, near-nothing for absence.
        // Deliberately not three opacities of the same mark.
        const skin = isLive
          ? "border-pass bg-pass"
          : isOn
            ? "border-dashed border-accent bg-transparent"
            : isPending
              ? "border-dotted border-accent bg-accent-wash"
              : "border-rule bg-paper";

        return (
          <span
            key={capability}
            role="img"
            aria-label={`${meta.label}: ${state}`}
            title={`${meta.label} — ${state}${"note" in meta ? ` (${meta.note})` : ""}`}
            className={`${CAP_CELL} h-[15px] border ${skin}`}
          />
        );
      })}
    </span>
  );
}

/** What the three cell states mean, once, next to the grid that uses them. */
export function CapabilityLegend() {
  const entries = [
    { skin: "border-pass bg-pass", meaning: "reporting scans" },
    { skin: "border-dashed border-accent", meaning: "enabled, not yet reporting" },
    { skin: "border-dotted border-accent bg-accent-wash", meaning: "pending install PR" },
    { skin: "border-rule bg-paper", meaning: "not enabled" },
  ];
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
      {entries.map((entry) => (
        <li key={entry.meaning} className="flex items-center gap-1.5">
          <span aria-hidden className={`inline-block h-[11px] w-[18px] border ${entry.skin}`} />
          <span className="font-mono text-[11px] text-ink-3">{entry.meaning}</span>
        </li>
      ))}
    </ul>
  );
}

/**
 * A labelled indicator light.
 *
 * Colour is never the only carrier: every light is followed by the state in
 * words, because "which of these dots is amber" is not a question a dashboard
 * should ask of anybody, and half the failure states here differ by one shade.
 *
 * `idle` and `off` are deliberately separate. Not enabled and enabled-but-
 * silent look identical if you only render an absence, and only one of them is
 * a problem.
 */
export type IndicatorTone = "ok" | "bad" | "warn" | "idle" | "off";

/** Exported so widgets shaped differently from a lamp+word (e.g. a button)
 *  still draw the same five colours rather than inventing a second palette
 *  for the same five facts. */
export const INDICATOR: Record<IndicatorTone, { lamp: string; word: string }> = {
  ok: { lamp: "bg-pass border-pass", word: "text-pass" },
  bad: { lamp: "bg-critical border-critical", word: "text-critical" },
  warn: { lamp: "bg-high border-high", word: "text-high" },
  idle: { lamp: "bg-paper border-ink-3", word: "text-ink-3" },
  off: { lamp: "bg-paper border-rule", word: "text-ink-3" },
};

export function IndicatorLight({
  tone,
  label,
  state,
  title,
  href,
}: {
  tone: IndicatorTone;
  label: string;
  /** The state in words. Rendered, not just announced. */
  state: string;
  title?: string;
  href?: string;
}) {
  const body = (
    <span className="flex items-baseline gap-1.5">
      <span
        aria-hidden
        className={`relative top-px inline-block h-2.5 w-2.5 shrink-0 border ${INDICATOR[tone].lamp}`}
      />
      <span className="font-mono text-[12px] text-ink-2">{label}</span>
      <span
        className={`font-mono text-[11px] uppercase tracking-[0.08em] ${INDICATOR[tone].word}`}
      >
        {state}
      </span>
    </span>
  );

  return (
    <li
      className="flex items-baseline"
      title={title ?? `${label} — ${state}`}
      aria-label={`${label}: ${state}`}
    >
      {href ? (
        <a
          href={href}
          target="_blank"
          rel="noreferrer"
          className="underline-offset-2 hover:underline"
        >
          {body}
        </a>
      ) : (
        body
      )}
    </li>
  );
}

/** What the colours mean, next to the lights that use them. */
export function IndicatorLegend({
  entries,
}: {
  entries: { tone: IndicatorTone; meaning: string }[];
}) {
  return (
    <ul className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
      {entries.map((entry) => (
        <li key={entry.meaning} className="flex items-baseline gap-1.5">
          <span
            aria-hidden
            className={`relative top-px inline-block h-2 w-2 shrink-0 border ${INDICATOR[entry.tone].lamp}`}
          />
          <span className="font-mono text-[11px] text-ink-3">{entry.meaning}</span>
        </li>
      ))}
    </ul>
  );
}

/** A titled block of the one dashboard, so every panel is labelled the same way. */
export function Section({
  title,
  detail,
  aside,
  children,
}: {
  title: string;
  detail?: ReactNode;
  aside?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="ticks border border-rule bg-paper-2">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-rule-soft px-3 py-2">
        <h2 className="font-mono text-[12px] font-bold uppercase tracking-[0.12em] text-ink">
          {title}
        </h2>
        {detail ? (
          <span className="font-mono text-[12px] text-ink-3">{detail}</span>
        ) : null}
        {aside ? <span className="ml-auto">{aside}</span> : null}
      </div>
      {children}
    </section>
  );
}

export function StatTile({
  label,
  value,
  sub,
  alert = false,
}: {
  label: string;
  value: ReactNode;
  sub?: string;
  alert?: boolean;
}) {
  return (
    <div
      // `ticks` here and not on every box: a stat tile is a measurement
      // somebody can go and check, which is exactly what the corner marks are
      // for. A mark on everything marks nothing.
      className={`ticks flex flex-col gap-0.5 border p-2.5 ${
        alert ? "border-critical bg-critical-wash" : "border-rule bg-paper-2"
      }`}
    >
      <Label>{label}</Label>
      <span
        className={`tabular text-2xl font-bold leading-none tracking-tight ${
          alert ? "text-critical" : ""
        }`}
      >
        {value}
      </span>
      {sub ? <span className="font-mono text-[11px] text-ink-3">{sub}</span> : null}
    </div>
  );
}

export function ErrorPanel({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="border border-critical bg-critical-wash p-4">
      <p className="text-sm font-semibold text-critical">{title}</p>
      <p className="mt-1 max-w-prose text-sm text-ink-2">{detail}</p>
    </div>
  );
}

export function EmptyState({ title, detail }: { title: string; detail: ReactNode }) {
  return (
    <div className="border border-dashed border-rule bg-paper-2 p-8 text-center">
      <p className="text-sm font-semibold">{title}</p>
      <p className="mx-auto mt-1 max-w-prose text-sm text-ink-3">{detail}</p>
    </div>
  );
}


/**
 * Oracle's verdict.
 *
 * `no_go` is coloured critical even though the gate is advisory by default.
 * The colour describes the finding, not the enforcement — softening it because
 * nothing is blocked would be the UI quietly disagreeing with the engine.
 *
 * Null is "not assessed", which is a real state and not the same as `go`.
 * Oracle is opt-in, so plenty of repos will sit here permanently.
 */
const RECOMMENDATION_TONE: Record<string, PillTone> = {
  no_go: "critical",
  review_recommended: "warn",
  go: "pass",
};

export function Verdict({
  recommendation,
  score,
}: {
  recommendation?: string | null;
  score?: number | null;
}) {
  if (!recommendation) {
    return (
      <span
        className="font-mono text-[12px] text-ink-3"
        title="Risk decisions are opt-in - this repository has not been judged"
      >
        not assessed
      </span>
    );
  }
  return (
    <span className="inline-flex items-baseline gap-1.5">
      <Pill tone={RECOMMENDATION_TONE[recommendation] ?? "muted"}>
        {recommendation.replace(/_/g, " ")}
      </Pill>
      {typeof score === "number" ? (
        <span className="tabular font-mono text-[12px] text-ink-3">{score}</span>
      ) : null}
    </span>
  );
}

/**
 * A 0–100 score as a filled track.
 *
 * The number alone is hard to place — is 63 bad? — and the thresholds are the
 * context that answers it, so they are drawn on the track as ticks rather than
 * left in the policy file.
 */
export function ScoreMeter({
  score,
  reviewAt = 30,
  noGoAt = 70,
}: {
  score: number;
  reviewAt?: number;
  noGoAt?: number;
}) {
  const tone =
    score >= noGoAt ? "bg-critical" : score >= reviewAt ? "bg-high" : "bg-pass";
  return (
    <span
      className="relative inline-block h-2.5 w-28 border border-rule bg-paper"
      role="img"
      aria-label={`Risk score ${score} of 100`}
    >
      <span
        className={`absolute inset-y-0 left-0 ${tone}`}
        style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
      />
      {[reviewAt, noGoAt].map((threshold) => (
        <span
          key={threshold}
          title={`${threshold === noGoAt ? "no go" : "review"} at ${threshold}`}
          className="absolute inset-y-0 w-px bg-ink-3 opacity-70"
          style={{ left: `${threshold}%` }}
        />
      ))}
    </span>
  );
}

export function Crumb({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link href={href} className="text-accent underline-offset-2 hover:underline">
      {children}
    </Link>
  );
}
