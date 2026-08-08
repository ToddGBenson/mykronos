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
 * Ten slots, one per capability, so coverage gaps read down the column.
 *
 * A repo missing Secrets is visible without reading a single word — which is
 * the thing a portfolio table is actually for.
 */
export const ALL_CAPABILITIES = [
  "sast",
  "dast",
  "secrets",
  "containers",
  "iac",
  "cloud",
  "aegis",
  "atlas",
  "patchwork",
  "oracle",
] as const;

export function CapabilityDots({
  enabled,
  pending = [],
}: {
  enabled: string[];
  pending?: string[];
}) {
  return (
    <span
      className="inline-flex gap-[2px]"
      role="img"
      aria-label={
        enabled.length ? `Enabled: ${enabled.join(", ")}` : "No capabilities enabled"
      }
    >
      {ALL_CAPABILITIES.map((capability) => {
        const isOn = enabled.includes(capability);
        const isPending = !isOn && pending.includes(capability);
        return (
          <span
            key={capability}
            title={`${capability}${isOn ? "" : isPending ? " (pending merge)" : " (off)"}`}
            className={`block h-[7px] w-[7px] border ${
              isOn
                ? "border-accent bg-accent"
                : isPending
                  ? "border-accent bg-transparent"
                  : "border-rule bg-transparent"
            }`}
          />
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


export function Crumb({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link href={href} className="text-accent underline-offset-2 hover:underline">
      {children}
    </Link>
  );
}
