/**
 * The Today run sheet (TheHub #61141), run rather than read: the words the
 * page puts beside each state, the headline, and the Watch step built from
 * the briefing's stalled and stale lanes.
 */
import { describe, expect, it } from "vitest";

import { STATE_META, headline, watchStep, type StepLike } from "../lib/today";

function step(key: string, state: StepLike["state"]): StepLike {
  return { key, title: key, state, summary: "", items: [], hidden: [], status: "ok", reason: "", notes: [] };
}

describe("STATE_META", () => {
  it("pairs every state with a word, so colour never carries it alone", () => {
    expect(STATE_META.ready.word).toBe("ready for you");
    expect(STATE_META.waiting.word).toBe("waiting");
    expect(STATE_META.blocked.word).toBe("blocked");
    expect(STATE_META.done.word).toBe("done");
    expect(STATE_META.unknown.word).toBe("not known");
  });
});

describe("headline", () => {
  it("counts the steps that need you and the ones waiting", () => {
    expect(
      headline([step("decide", "ready"), step("merge", "ready"), step("deploy", "waiting"), step("tasks", "done")]),
    ).toBe("2 steps need you · 1 waiting");
  });

  it("says one step, not one steps, and names unknown steps", () => {
    expect(headline([step("decide", "ready"), step("merge", "unknown")])).toBe(
      "1 step needs you · 1 could not be read",
    );
  });

  it("says when nothing needs you", () => {
    expect(headline([step("decide", "done"), step("deploy", "done")])).toBe("nothing needs you today");
  });
});

describe("watchStep", () => {
  const stalled = {
    repo_full_name: "acme/beacon",
    capability: "sast",
    reason: "failing",
    detail: "errored 3 times",
    days_since_run: 0.2,
    usual_gap_days: 1,
    open_findings: 12,
  };

  it("lists failing, silent and blocked lanes as items with their reason", () => {
    const watch = watchStep(
      [
        stalled,
        { ...stalled, repo_full_name: "acme/orchard", capability: "dast", reason: "silent", days_since_run: 1.1 },
      ],
      [],
    );
    expect(watch.state).toBe("waiting");
    expect(watch.summary).toBe("1 lane red, 1 silent");
    expect(watch.items.map((i) => i.text)).toEqual(["acme/beacon / sast", "acme/orchard / dast"]);
    expect(watch.items[0].reason).toBe("failing: errored 3 times · 12 open findings frozen");
    expect(watch.items[1].reason).toBe("silent 26h · 12 open findings frozen");
    expect(watch.items.every((i) => i.owner === "an agent")).toBe(true);
  });

  it("adds stale lanes, which report but do not cover", () => {
    const watch = watchStep([], [
      { repo_full_name: "acme/relay", capability: "secrets", reason: "same_commit", runs: 4, open_findings: 2 },
    ]);
    expect(watch.items[0].reason).toBe("reporting on an old commit (4 runs) · 2 open findings frozen");
    expect(watch.summary).toBe("1 stale");
  });

  it("is done when every lane is covering", () => {
    const watch = watchStep([], []);
    expect(watch.state).toBe("done");
    expect(watch.summary).toBe("every lane is running");
  });

  it("is unknown, never done, when the briefing could not be read", () => {
    const watch = watchStep(null, null, "The briefing is down.");
    expect(watch.state).toBe("unknown");
    expect(watch.status).toBe("unavailable");
    expect(watch.reason).toBe("The briefing is down.");
  });
});
