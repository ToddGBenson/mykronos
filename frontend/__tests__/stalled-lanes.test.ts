/**
 * The stalled-lanes idle note (#330), run rather than read.
 *
 * "Nothing is stuck behind these" is only true of a lane with no jobs held
 * behind it; a lane gating others must say how many and which.
 */
import { describe, expect, it } from "vitest";

import { idleNotes } from "../lib/stalled-lanes";

const unit = {
  repo_full_name: "ToddGBenson/mykronos",
  capability: "unit",
  held_behind: ["ai", "build", "dependencies", "iac", "insider", "sast", "secrets"],
};
const iac = { repo_full_name: "ToddGBenson/personal-soc", capability: "iac", held_behind: [] };

describe("idleNotes", () => {
  it("names the jobs held behind a lane instead of saying nothing is stuck", () => {
    const [note, ...rest] = idleNotes([unit], true);
    expect(rest).toEqual([]);
    expect(note).toBe(
      "Also stalled, holding nothing open: ToddGBenson/mykronos unit. 7 jobs are held " +
        "behind it and cannot run until it is green: ai, build, dependencies, iac, insider, " +
        "sast, secrets.",
    );
    expect(note).not.toContain("Nothing is stuck");
  });

  it("says 1 job, not 1 jobs", () => {
    expect(idleNotes([{ ...unit, held_behind: ["containers"] }], true)[0]).toContain(
      "1 job is held behind it",
    );
  });

  it("keeps the old sentence only for lanes nothing waits on, and sorts gating lanes first", () => {
    const notes = idleNotes([iac, unit], true);
    expect(notes).toHaveLength(2);
    expect(notes[0]).toContain("ToddGBenson/mykronos unit. 7 jobs are held behind it");
    expect(notes[1]).toBe(
      "Also stalled, holding nothing open: ToddGBenson/personal-soc iac. Nothing is stuck " +
        "behind these, but they are not watching either.",
    );
  });

  it("orders gating lanes by how much they hold back", () => {
    const one = { ...iac, capability: "build", held_behind: ["containers"] };
    const notes = idleNotes([one, unit], true);
    expect(notes[0]).toContain("mykronos unit");
    expect(notes[1]).toContain("personal-soc build");
  });

  it("treats a missing field as nothing held, as an older backend would send", () => {
    const { held_behind: _drop, ...bare } = unit;
    void _drop;
    expect(idleNotes([bare], true)[0]).toContain("Nothing is stuck behind these");
  });

  it("drops 'Also' when nothing was listed above it", () => {
    const notes = idleNotes([unit, iac], false);
    expect(notes[0].startsWith("Stalled, holding nothing open")).toBe(true);
    expect(notes[1].startsWith("Also stalled")).toBe(true);
    expect(idleNotes([iac], false)[0].startsWith("Stalled, holding")).toBe(true);
  });

  it("says nothing when there are no idle lanes", () => {
    expect(idleNotes([], true)).toEqual([]);
  });
});
