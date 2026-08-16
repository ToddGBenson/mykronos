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

export function Label({ children }: { children: ReactNode }) {
  return (
    <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-3">
      {children}
    </span>
  );
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
      className={`font-mono text-[10px] font-bold uppercase tracking-[0.08em] ${SEVERITY_CLASS[severity]}`}
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

export function Pill({ tone, children }: { tone: PillTone; children: ReactNode }) {
  return (
    <span
      className={`inline-block whitespace-nowrap border px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-[0.08em] ${PILL[tone]}`}
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
  unit: { icon: "🧪", label: "Unit tests" },
  qa: { icon: "📋", label: "QA / docs quality" },
  sast: { icon: "🔍", label: "Static analysis (SAST)" },
  secrets: { icon: "🔑", label: "Secret scanning" },
  atlas: { icon: "📦", label: "Dependencies (SCA)" },
  containers: { icon: "🐳", label: "Container scanning" },
  iac: { icon: "🏗️", label: "Infrastructure as code" },
  functional: { icon: "🧭", label: "Functional tests" },
  dast: { icon: "🕷️", label: "Dynamic analysis (DAST)" },
  cloud: { icon: "☁️", label: "Cloud posture" },
  network: { icon: "🌐", label: "Network scanning" },
  ai: { icon: "✨", label: "AI checks" },
  aegis: { icon: "🛡️", label: "Insider risk (Aegis)" },
  oracle: { icon: "⚖️", label: "Risk decisions (Oracle)" },
  patchwork: { icon: "🩹", label: "Auto-remediation (Patchwork)" },
} as const;

export const ALL_CAPABILITIES = Object.keys(
  CAPABILITY_META,
) as (keyof typeof CAPABILITY_META)[];

export function CapabilityDots({
  enabled,
  pending = [],
  live = [],
}: {
  enabled: string[];
  pending?: string[];
  /**
   * Capabilities that have actually reported a scan. Implemented-but-silent
   * and implemented-and-reporting are different facts: the first is dimmed,
   * the second is full-strength. Without the distinction, "enabled" quietly
   * claims coverage that may not exist — the unit lane was enabled and had
   * never reported once.
   */
  live?: string[];
}) {
  return (
    <span
      className="inline-flex items-center gap-[3px]"
      role="img"
      aria-label={
        enabled.length ? `Enabled: ${enabled.join(", ")}` : "No capabilities enabled"
      }
    >
      {ALL_CAPABILITIES.map((capability) => {
        const meta = CAPABILITY_META[capability];
        const isOn = enabled.includes(capability);
        const isLive = isOn && live.includes(capability);
        const isPending = !isOn && pending.includes(capability);
        return (
          <span
            key={capability}
            title={`${meta.label}${
              isLive
                ? " — live"
                : isOn
                  ? " — enabled, not yet reporting"
                  : isPending
                    ? " — pending install PR"
                    : " — not enabled"
            }`}
            className={`text-[11px] leading-none ${
              isLive
                ? ""
                : isOn || isPending
                  ? "opacity-45 saturate-50"
                  : "opacity-15 grayscale"
            }`}
          >
            {meta.icon}
          </span>
        );
      })}
    </span>
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
      className={`flex flex-col gap-0.5 border p-2.5 ${
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
      {sub ? <span className="font-mono text-[9px] text-ink-3">{sub}</span> : null}
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
        className="font-mono text-[10px] text-ink-3"
        title="Oracle is opt-in and has not judged this repository"
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
        <span className="tabular font-mono text-[10px] text-ink-3">{score}</span>
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
