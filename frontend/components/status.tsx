import { STATUS, type Status, type StatusIcon } from "@/lib/status";

/**
 * A state, drawn with its colour, its icon and its word (TheHub #61135).
 *
 * The class names are spelled out in full rather than built from the token,
 * because Tailwind only generates classes it can find written in the source.
 */
const FILL: Record<string, string> = {
  ok: "bg-ok",
  fail: "bg-fail",
  stale: "bg-stale",
  warn: "bg-warn",
  ready: "bg-ready",
  accepted: "bg-accepted",
};

const PATHS: Record<StatusIcon, string> = {
  tick: "M3.5 8.5l3 3 6-7",
  cross: "M4.5 4.5l7 7M11.5 4.5l-7 7",
  clock: "M8 2.5a5.5 5.5 0 1 0 0 11a5.5 5.5 0 1 0 0-11M8 5v3.2l2.2 1.4",
  ring: "M8 2.5a5.5 5.5 0 1 0 0 11a5.5 5.5 0 1 0 0-11",
  shield: "M8 2l5 2v4c0 3-2.2 5-5 6c-2.8-1-5-3-5-6V4z",
  triangle: "M8 2.5l6 11H2zM8 6.5v3.5M8 11.6v.4",
  dot: "M8 5a3 3 0 1 0 0 6a3 3 0 1 0 0-6",
};

export function StatusIconGlyph({ icon, className = "" }: { icon: StatusIcon; className?: string }) {
  return (
    <svg
      viewBox="0 0 16 16"
      width="14"
      height="14"
      aria-hidden="true"
      focusable="false"
      className={`shrink-0 ${className}`}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeDasharray={icon === "ring" ? "2.2 2" : undefined}
    >
      <path d={PATHS[icon]} />
    </svg>
  );
}

/**
 * A pill: solid fill with `on-fill` text, or, for never-scanned, a dashed
 * outline with no fill. `label` replaces the visible word (a tile shows "3h"),
 * and the word stays for screen readers.
 */
export function StatusPill({ status, label }: { status: Status; label?: string }) {
  const { word, icon, token } = STATUS[status];
  const skin =
    token in FILL
      ? `${FILL[token]} text-on-fill`
      : "border-[1.5px] border-dashed border-ink-3 text-ink-2";
  return (
    <span
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-[11.5px] font-semibold ${skin}`}
    >
      <StatusIconGlyph icon={icon} />
      {label ? (
        <>
          {label}
          <span className="sr-only"> {word}</span>
        </>
      ) : (
        word
      )}
    </span>
  );
}
