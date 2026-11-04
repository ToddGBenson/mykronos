/**
 * Raise a Hub incident or story from where the problem is seen (TheHub #60911).
 *
 * The control sits on a failing lane, a health dependency row and a finding.
 * Before anything is raised it offers "Raise in TheHub". Once raised, the row
 * shows the linked Hub id and its live status, and a status that could not be
 * read says so.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { RaiseToHub } from "@/components/raise-to-hub";
import { hubLinkText, raisedLookup } from "@/lib/raise-to-hub";

describe("RaiseToHub", () => {
  it("offers to raise when nothing is linked", () => {
    const html = renderToStaticMarkup(
      createElement(RaiseToHub, { kind: "lane", subject: "o/beacon:sast", link: null }),
    );
    expect(html).toContain("Raise in TheHub");
    expect(html).toContain('data-raise-kind="lane"');
  });

  it("shows the linked Hub id and its status once raised", () => {
    const html = renderToStaticMarkup(
      createElement(RaiseToHub, {
        kind: "finding",
        subject: "f-1",
        link: {
          subject: "f-1",
          hub_kind: "incident",
          hub_id: 901,
          status: "acknowledged",
          raised_by: "operator",
          raised_at: "2026-11-01T10:00:00",
        },
      }),
    );
    expect(html).toContain("TheHub incident #901");
    expect(html).toContain("acknowledged");
    expect(html).toContain("operator");
  });
});

describe("hubLinkText", () => {
  it("says a status that could not be read is unknown", () => {
    expect(
      hubLinkText({
        subject: "s",
        hub_kind: "story",
        hub_id: 7,
        status: "unknown",
        raised_by: "a",
        raised_at: null,
      }),
    ).toBe("TheHub story #7 · status unknown");
  });
});

describe("raisedLookup", () => {
  it("indexes the links by subject, and a failed read is an empty map, not a crash", () => {
    const map = raisedLookup({
      ok: true,
      data: {
        links: [
          { subject: "a", hub_kind: "incident", hub_id: 1, status: "open", raised_by: "x", raised_at: null },
        ],
      },
    });
    expect(map.get("a")?.hub_id).toBe(1);
    expect(raisedLookup({ ok: false, error: "HTTP 500" }).size).toBe(0);
  });
});
