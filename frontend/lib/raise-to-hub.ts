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

/** What the control shows for a subject that was already raised and is still open. */
export function alreadyRaisedText(link: RaisedLink): string {
  return `TheHub ${link.hub_kind} #${link.hub_id} · already raised, so nothing new was filed (the title and note were not sent)`;
}

/**
 * The link the control shows for the backend's answer to a raise. A 201 is
 * raised by you, just now. `already_raised` is an item that was there before:
 * it is not claimed as yours, and it has no time.
 */
export function raisedFromAnswer(
  subject: string,
  answer: { hub_kind: string; hub_id: number; already_raised?: boolean },
  now: Date,
): { link: RaisedLink; already: boolean } {
  const already = answer.already_raised === true;
  return {
    already,
    link: {
      subject,
      hub_kind: answer.hub_kind,
      hub_id: answer.hub_id,
      status: "open",
      raised_by: already ? "an earlier raise" : "you",
      raised_at: already ? null : now.toISOString(),
    },
  };
}

/** The links by subject. A failed read is an empty map: the rows still offer to raise. */
export function raisedLookup(read: RaisedRead): Map<string, RaisedLink> {
  const map = new Map<string, RaisedLink>();
  if (!read.ok) return map;
  for (const link of read.data.links) map.set(link.subject, link);
  return map;
}
