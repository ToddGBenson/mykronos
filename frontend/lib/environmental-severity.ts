/**
 * Words and links for the "Severity here" block and environmental severity
 * (TheHub #60824, #60828): the vector's provenance and the v4.0 not-rescored
 * line, the facts behind a rescore, the Findings list's effective column and
 * summary, and the Threat Model tab's coverage line. One module, so the
 * vector is named the same way everywhere.
 *
 * The block is computed from one vector, chosen NVD 3.x > the scanner's
 * advisory 3.x > v4.0. CVSS 3.1 is primary; a v4.0 vector is shown and never
 * rescored (D1), because the environmental formula implemented here is v3's.
 *
 * Pure, so the wording is tested without rendering a page. Every count here is
 * the backend's — `by_rescoring` and `component_coverage` are counted over the
 * same scope as the list each one links to — and nothing is counted off a page
 * of groups, which is deduplicated and capped.
 */

/** One fact the resolver considered, as `SeverityHereOut.facts[]` carries it. */
export type EnvFact = {
  metric: string;
  value: string;
  direction: string;
  source_kind: string;
  source_id: string;
  tier: string;
  asserted_by: string;
  verified_at?: string | null;
  expires_at?: string | null;
  applied: boolean;
  not_applied_reason?: string | null;
  because?: string;
  scope?: string | null;
  evidence_id?: string | null;
};

/** The empty states, word for word, so the page and the tests agree. */
export const NOBODY_STATED = "Nobody has stated anything about this environment";
export const NO_VECTOR = "No vector: not rescorable";

const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** What the "Severity here" block needs to name its vector. */
export type HereVector = {
  vector_source?: string | null;
  vector_version?: string | null;
  rescored?: boolean;
  base?: number | null;
};

/**
 * The one line shown in place of the scores when only v4.0 exists, or `null`
 * when the vector was rescored and the scores speak for themselves.
 */
export function notRescoredLine(here: HereVector): string | null {
  if (here.rescored !== false) return null;
  const version = `v${here.vector_version ?? "4.0"}`;
  return typeof here.base === "number"
    ? `${version} base ${here.base.toFixed(1)}, not rescored`
    : `${version}, no base score published, not rescored`;
}

/**
 * `NVD v3.1`, `scanner advisory v3.1`, `analyst v3.1`: where the vector came
 * from. A number is only as good as its source, so it is named beside the
 * vector rather than left implied.
 */
export function vectorProvenance(here: HereVector): string {
  const source =
    here.vector_source === "advisory"
      ? "scanner advisory"
      : here.vector_source === "analyst"
        ? "analyst"
        : here.vector_source === "nvd"
          ? "NVD"
          : "source not recorded";
  return here.vector_version ? `${source} v${here.vector_version}` : source;
}

/** `down`, `up` or `same`: the effective word against the scanner's. */
export function shift(
  scanner: string | null | undefined,
  effective: string | null | undefined,
): "down" | "up" | "same" {
  const a = SEVERITY_RANK[scanner ?? ""];
  const b = SEVERITY_RANK[effective ?? ""];
  if (a === undefined || b === undefined || a === b) return "same";
  return b < a ? "down" : "up";
}

/** Applied first, then not applied, each in the resolver's order. */
export function splitFacts<T extends EnvFact>(facts: T[]): { applied: T[]; notApplied: T[] } {
  return {
    applied: facts.filter((fact) => fact.applied),
    notApplied: facts.filter((fact) => !fact.applied),
  };
}

/** `MAV:A` — the metric and the value the fact would set. */
export function factSetting(fact: EnvFact): string {
  return `${fact.metric}:${fact.value}`;
}

/** Why a fact did not count, or that it did. Never blank: an unapplied fact
 *  with no reason recorded says so rather than reading as applied. */
export function factOutcome(fact: EnvFact): string {
  if (fact.applied) return "applied";
  const reason = (fact.not_applied_reason ?? "").trim();
  return reason ? `not applied: ${reason}` : "not applied: no reason recorded";
}

export type FactSource = { label: string; href: string | null };

/**
 * Where a fact came from, as a link to the thing that says it.
 *
 * Surfaces and controls are on the Threat Model tab, anchored by id; the risk
 * profile is on the Risk Decision tab. A MAC pairing names a row of
 * `environment-map-v1.yaml`, which has no page, so its link is the surface it
 * applies to when it has one and otherwise the tab. An adapter's own tag is
 * about this finding, so it links nowhere.
 */
export function factSource(repoId: string, fact: EnvFact): FactSource {
  const repo = `/repos/${encodeURIComponent(repoId)}`;
  const id = encodeURIComponent(fact.source_id);
  switch (fact.source_kind) {
    case "surface":
      return { label: "surface", href: `${repo}?tab=threat-model#surface-${id}` };
    case "control":
      return { label: "control", href: `${repo}?tab=threat-model#control-${id}` };
    case "risk_profile":
      return { label: "risk profile", href: `${repo}?tab=decisions#risk-profile` };
    case "observation":
      return {
        label: `observation (${fact.source_id})`,
        href: fact.scope
          ? `${repo}?tab=threat-model#surface-${encodeURIComponent(fact.scope)}`
          : `${repo}?tab=threat-model`,
      };
    case "adapter_tag":
      return { label: "the scanner's own tag on this finding", href: null };
    default:
      return { label: fact.source_kind || "unknown source", href: null };
  }
}

/** `observed by exposure-sweep` or `declared by alice`, and the tier is what a
 *  reader weighs: only observed evidence can lower exploitability. */
export function factAttribution(fact: EnvFact): string {
  const who = fact.asserted_by ? ` by ${fact.asserted_by}` : "";
  return `${fact.tier}${who}`;
}

/**
 * The sentence above the facts. Three different states, and each one needs
 * its own words: nothing stated, stated and not counted, and counted.
 */
export function factsHeadline(facts: EnvFact[]): string {
  if (facts.length === 0) return `${NOBODY_STATED}.`;
  const { applied, notApplied } = splitFacts(facts);
  if (applied.length === 0) {
    return `${notApplied.length} statement${notApplied.length === 1 ? "" : "s"} about this environment, none of them evidence enough to apply.`;
  }
  return `${applied.length} applied, ${notApplied.length} not applied.`;
}

export type RescoreChip = {
  /** The `rescored` query value. */
  value: "down" | "up" | "not_rescorable";
  label: string;
  count: number;
  active: boolean;
};

/**
 * "N rescored down (verified), M rescored up, K not rescorable", as chips
 * that filter to exactly that many. Down says "(verified)" because the
 * resolver lowers only on observed or confirmed facts — true of the rule, not
 * a second check here. `unchanged` is counted by the backend and not shown:
 * it is the remainder, and a chip for it would say nothing to act on.
 */
export function rescoreChips(
  byRescoring: Record<string, number> | undefined,
  query: { rescored?: string },
): RescoreChip[] {
  const counts = byRescoring ?? {};
  const chip = (value: RescoreChip["value"], label: string): RescoreChip => ({
    value,
    label,
    count: counts[value] ?? 0,
    // `rescored` may carry several values (`rescored=down,up`).
    active: (query.rescored ?? "").split(",").includes(value),
  });
  return [
    chip("down", "rescored down (verified)"),
    chip("up", "rescored up"),
    chip("not_rescorable", "not rescorable"),
  ];
}

/** The same three, as one line of prose. */
export function rescoreSentence(byRescoring: Record<string, number> | undefined): string {
  return rescoreChips(byRescoring, {})
    .map((entry) => `${entry.count} ${entry.label}`)
    .join(", ");
}

export type Coverage = {
  open_findings: number;
  unplaced: number;
  surfaces: number;
  located_surfaces: number;
};

/**
 * The Threat Model tab's coverage line, and whether it needs a link. Zero
 * unplaced is said rather than hidden — it is the result somebody declared
 * selectors to reach.
 */
export function coverageLine(coverage: Coverage): { text: string; detail: string; link: boolean } {
  const n = coverage.unplaced;
  const text = `${n} open finding${n === 1 ? "" : "s"} map${n === 1 ? "s" : ""} to no component`;
  let detail: string;
  if (coverage.open_findings === 0) {
    detail = "There are no open findings to place.";
  } else if (coverage.surfaces === 0) {
    detail = "No surface is declared, so nothing can be placed. Declare one with selectors above.";
  } else if (coverage.located_surfaces === 0) {
    detail = "No declared surface has selectors, and a surface without them places nothing.";
  } else if (n === 0) {
    detail = `Every one of ${coverage.open_findings} open findings is in a declared surface.`;
  } else {
    detail = `Of ${coverage.open_findings} open. They are rescored on repository-level facts only, where lowering needs observed evidence.`;
  }
  return { text, detail, link: n > 0 };
}
