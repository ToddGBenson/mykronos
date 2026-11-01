import Link from "next/link";

import { checkHref } from "@/lib/checks";
import { findingsHref } from "@/lib/findings-filters";
import {
  LEGEND,
  TILE_WORD,
  tileValue,
  tileWords,
  type Tile,
  type TileState,
} from "@/lib/portfolio-board";

/**
 * The board's tiles and legend (TheHub #61138). Every state is drawn three
 * ways at once: a colour, an icon, and a word in the tile's accessible name.
 * A stale tile also has a hatched foot and a never-scanned one a dashed
 * outline, so the board still reads in greyscale.
 *
 * The fill colours fall back to tokens main already has. Once the v2 palette
 * (#61135) lands, `--color-accepted` and `--color-on-fill` take over.
 */

const ON_FILL = "text-[var(--color-on-fill,var(--color-paper))]";

const SKIN: Record<TileState, string> = {
  healthy: `border-pass bg-pass ${ON_FILL}`,
  failing: `border-critical bg-critical ${ON_FILL}`,
  overdue: `border-high bg-high ${ON_FILL}`,
  accepted: `border-[var(--color-accepted,var(--color-medium))] bg-[var(--color-accepted,var(--color-medium))] ${ON_FILL}`,
  stale: "border-ink-3 bg-paper-2 text-ink",
  never: "border-dashed border-ink-3 bg-transparent text-ink-3",
};

/** Small, stroke-only marks, so they hold on a fill and on paper alike. */
export function TileIcon({ state, className = "h-3.5 w-3.5" }: { state: TileState; className?: string }) {
  const common = {
    className,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
    focusable: false,
  };
  switch (state) {
    case "healthy":
      return (
        <svg {...common}>
          <path d="M3 8.5l3.2 3L13 4.5" />
        </svg>
      );
    case "failing":
      return (
        <svg {...common}>
          <path d="M4 4l8 8M12 4l-8 8" />
        </svg>
      );
    case "stale":
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="6" />
          <path d="M8 4.5V8l2.5 1.5" />
        </svg>
      );
    case "never":
      return (
        <svg {...common} strokeDasharray="2.2 2.2">
          <circle cx="8" cy="8" r="6" />
        </svg>
      );
    case "accepted":
      return (
        <svg {...common}>
          <path d="M8 1.8l5.2 2v4c0 3.2-2.3 5.4-5.2 6.4-2.9-1-5.2-3.2-5.2-6.4v-4z" />
        </svg>
      );
    case "overdue":
      return (
        <svg {...common}>
          <path d="M8 2l6.5 11.5h-13z" />
          <path d="M8 6.5v3M8 11.8v.2" />
        </svg>
      );
  }
}

/** Where a tile opens: the findings it counts, or the check's run history. */
export function tileHref(repoId: string, capability: string, tile: Tile): string {
  if (tile.state === "overdue") return findingsHref(repoId, { capability, due: "overdue" });
  if (tile.state === "accepted") {
    return findingsHref(repoId, { capability, status: "accepted_risk" });
  }
  return checkHref(repoId, capability);
}

export function BoardTile({
  repoId,
  capability,
  short,
  label,
  tile,
  now,
}: {
  repoId: string;
  capability: string;
  short: string;
  label: string;
  tile: Tile;
  now: number;
}) {
  const words = tileWords(tile, now);
  return (
    <Link
      href={tileHref(repoId, capability, tile)}
      data-tile={capability}
      aria-label={`${label}: ${words}`}
      title={`${label}: ${words}`}
      className={`relative flex min-h-11 flex-col justify-between overflow-hidden border px-1.5 pb-1.5 pt-1 font-mono focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent hover:outline hover:outline-1 hover:outline-accent sm:min-h-14 ${SKIN[tile.state]}`}
    >
      <span className="flex items-center justify-between gap-1 text-[11px] font-semibold leading-tight">
        <span className="truncate">{short}</span>
        <TileIcon state={tile.state} className="h-3.5 w-3.5 shrink-0" />
      </span>
      <span className="tabular text-[13px] font-bold leading-none">{tileValue(tile, now)}</span>
      {tile.state === "stale" ? (
        <span
          aria-hidden
          className="absolute inset-x-0 bottom-0 h-1.5 bg-[repeating-linear-gradient(135deg,var(--color-ink-3)_0_2px,transparent_2px_5px)]"
        />
      ) : null}
    </Link>
  );
}

/** The six states, each with its swatch, icon and word. */
export function BoardLegend() {
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-2" aria-label="Tile states">
      {LEGEND.map((state) => (
        <li key={state} className="flex items-center gap-1.5">
          <span
            aria-hidden
            className={`relative inline-flex h-5 w-7 items-center justify-center overflow-hidden border ${SKIN[state]}`}
          >
            <TileIcon state={state} className="h-3 w-3" />
            {state === "stale" ? (
              <span className="absolute inset-x-0 bottom-0 h-1 bg-[repeating-linear-gradient(135deg,var(--color-ink-3)_0_2px,transparent_2px_5px)]" />
            ) : null}
          </span>
          <span className="font-mono text-[12px] text-ink-2">{TILE_WORD[state]}</span>
        </li>
      ))}
    </ul>
  );
}
