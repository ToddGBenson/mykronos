/**
 * Raise a Hub incident or story from where the problem is seen (TheHub #60911).
 *
 * Pure helpers shared by the control and the pages that place it. The
 * backend builds the evidence; the browser only says what and where.
 */

import type { components } from "./api-types";

export type RaiseKind = "lane" | "finding" | "health";
export type RaisedLink = components["schemas"]["RaisedLinkOut"];
export type RaisedRead = { ok: true; data: { links: RaisedLink[] } } | { ok: false; error: string };

/** "TheHub incident #901 · acknowledged", and an unread status said as such. */
export function hubLinkText(link: RaisedLink): string {
  const status = link.status === "unknown" ? "status unknown" : link.status;
  return `TheHub ${link.hub_kind} #${link.hub_id} · ${status}`;
}

/** The links by subject. A failed read is an empty map: the rows still offer to raise. */
export function raisedLookup(read: RaisedRead): Map<string, RaisedLink> {
  const map = new Map<string, RaisedLink>();
  if (!read.ok) return map;
  for (const link of read.data.links) map.set(link.subject, link);
  return map;
}
