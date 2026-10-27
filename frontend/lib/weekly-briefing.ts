/**
 * The weekly intelligence page's reasoning (TheHub #60865, B7): where an
 * item's source leads, what each confidence means, and how a page is
 * summarised. Kept out of the component so it can be tested without
 * rendering.
 */

import type { components } from "./api-types";

export type WeeklyBriefing = components["schemas"]["WeeklyBriefingOut"];
export type WeeklyPage = components["schemas"]["WeeklyPageOut"];
export type WeeklySection = components["schemas"]["WeeklySectionOut"];
export type WeeklyItem = components["schemas"]["WeeklyItemOut"];

/** Where an item's source leads: an advisory out, a MyKronos record in. */
export function sourceLink(source: string): { href: string; external: boolean } | null {
  if (source.startsWith("https://")) return { href: source, external: true };
  if (source.startsWith("/repos/")) return { href: source, external: false };
  return null;
}

export const CONFIDENCE_WORD: Record<WeeklyItem["confidence"], string> = {
  observed: "Observed",
  inferred: "Inferred",
};

/** The flash items on a page: exploited or critical, and shipped. */
export function flashes(page: WeeklyPage): WeeklyItem[] {
  return page.sections.flatMap((section) => section.items ?? []).filter((item) => item.flash);
}

/** How many items are new in the page's week, each section counted. */
export function newThisWeek(page: WeeklyPage): number {
  return page.sections
    .flatMap((section) => section.items ?? [])
    .filter((item) => item.new_this_week).length;
}

/** `/briefing/weekly`, or one application's page. */
export function weeklyHref(repoId: string | null): string {
  return repoId ? `/briefing/weekly?repo_id=${encodeURIComponent(repoId)}` : "/briefing/weekly";
}
