/**
 * The stalled-lanes note for lanes holding no findings open (#330). Pure, so
 * the vitest suite runs it.
 *
 * "Holding nothing open" is about findings. It says nothing about the CI jobs
 * gated on the lane, and this page told a reader "Nothing is stuck behind
 * these" about `mykronos unit` while seven scanners were held behind it. The
 * sentences follow `mykronos briefing`'s idle note: a lane with jobs behind it
 * names them and sorts first, and the old sentence is kept only for the lanes
 * it is true of.
 */

export type IdleLane = {
  repo_full_name: string;
  capability: string;
  /** The jobs held behind the lane, from the backend; absent reads as none. */
  held_behind?: string[];
};

/**
 * One sentence per idle lane that gates jobs, then one for the rest.
 * `preceded` is whether a lane holding findings was listed above: "Also"
 * needs something to be also to.
 */
export function idleNotes(idle: IdleLane[], preceded: boolean): string[] {
  const held = (lane: IdleLane) => lane.held_behind ?? [];
  // Stable, so lanes holding equally many keep the order the backend gave.
  const gating = idle.filter((lane) => held(lane).length).sort((a, b) => held(b).length - held(a).length);
  const quiet = idle.filter((lane) => !held(lane).length);

  const notes: string[] = [];
  let also = preceded;
  for (const lane of gating) {
    const jobs = held(lane);
    const count = jobs.length === 1 ? "1 job is" : `${jobs.length} jobs are`;
    notes.push(
      `${also ? "Also stalled" : "Stalled"}, holding nothing open: ${lane.repo_full_name} ` +
        `${lane.capability}. ${count} held behind it and cannot run until it is green: ` +
        `${jobs.join(", ")}.`,
    );
    also = true;
  }
  if (quiet.length) {
    const names = quiet.map((lane) => `${lane.repo_full_name} ${lane.capability}`).join(", ");
    notes.push(
      `${also ? "Also stalled" : "Stalled"}, holding nothing open: ${names}. ` +
        "Nothing is stuck behind these, but they are not watching either.",
    );
  }
  return notes;
}
