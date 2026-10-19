/**
 * Words for the triage queue's rank (spec 27 §1, TheHub #60829): one line per
 * rank term, and the caveat under the order switch saying what the order is
 * made of.
 *
 * The backend writes every term's `detail`, including the environmental
 * term's fact summary ("rescored down 1 band: MAV:L from observed ..."), so
 * this module only decides how a term reads at a glance: its signed points,
 * and whether it is a zero that answers something (no score, a lapsed one, a
 * move inside one band) rather than a term that did nothing.
 *
 * Pure, so the wording is tested without rendering a page.
 */

/** One rank term, as `TriageItem.rank_terms[]` carries it. */
export type RankTerm = { key: string; points: number; detail: string };

/** The environmental term's key, as `RANK_INPUTS` declares it. */
export const ENVIRONMENTAL = "environmental";

/** `+25`, `−10` (a real minus sign), `±0`. Zero is signed so it reads as an
 *  answer beside the others rather than a missing number. */
export function signedPoints(points: number): string {
  const rounded = Math.round(points * 100) / 100;
  if (rounded === 0) return "±0";
  return rounded > 0 ? `+${rounded}` : `−${Math.abs(rounded)}`;
}

export type RankTermLine = {
  points: string;
  detail: string;
  /** For styling: an environmental term that moved the rank down, up, or
   *  not at all. Other terms are `null`. */
  environmental: "down" | "up" | "none" | null;
};

/** How one term reads beside a queue row. */
export function rankTermLine(term: RankTerm): RankTermLine {
  const environmental =
    term.key !== ENVIRONMENTAL
      ? null
      : term.points < 0
        ? "down"
        : term.points > 0
          ? "up"
          : "none";
  return {
    points: signedPoints(term.points),
    detail: environmental ? `environment: ${term.detail}` : term.detail,
    environmental,
  };
}

/** What `RankingInputs.environmental` carries. Optional so an older backend
 *  that sends no block still renders. */
export type EnvironmentalRank = {
  weight_per_band: number;
  scored: number;
  lapsed: number;
  unscored: number;
  description: string;
};

/**
 * The sentence after "Not consulted: business context — <reason>." Three
 * states, each with its own claim: no score in force anywhere (a severity and
 * threat-intel order), some (business context reaches part of the order),
 * and the block missing from an older backend (the old sentence, which was
 * true of it).
 */
export function rankingCaveat(environmental: EnvironmentalRank | null | undefined): string {
  if (!environmental) {
    return "This order is severity and threat intelligence, not business risk.";
  }
  const total = environmental.scored + environmental.lapsed + environmental.unscored;
  if (environmental.scored === 0) {
    return "This order is severity and threat intelligence, not business risk: no open finding has an environmental score in force.";
  }
  return `Business context reaches this order only through environmental scores, which ${environmental.scored} of ${total} open findings have.`;
}

/** The one line describing the environmental term, shown with the order
 *  whether or not anything is unconsulted. */
export function environmentalLine(environmental: EnvironmentalRank | null | undefined): string | null {
  if (!environmental) return null;
  const lapsed =
    environmental.lapsed > 0
      ? ` ${environmental.lapsed} set aside until rescored: a fact they rest on expired.`
      : "";
  return `${capitalise(environmental.description)}.${lapsed}`;
}

function capitalise(text: string): string {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : text;
}
