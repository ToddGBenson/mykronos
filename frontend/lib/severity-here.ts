/**
 * Words for the "Severity here" block's vector (TheHub #60824).
 *
 * The block is computed from one vector, chosen NVD 3.x > the scanner's
 * advisory 3.x > v4.0. CVSS 3.1 is primary; a v4.0 vector is shown and never
 * rescored (D1), because the environmental formula implemented here is v3's.
 * Pure so it can be tested without rendering the page.
 */

export type HereVector = {
  vector_source?: "nvd" | "advisory";
  vector_version?: string;
  rescored?: boolean;
  base?: number | null;
};

/** `NVD v3.1` or `scanner advisory v3.1`: where the vector came from. */
export function vectorProvenance(here: HereVector): string {
  const source = here.vector_source === "advisory" ? "scanner advisory" : "NVD";
  return `${source} v${here.vector_version ?? "3.1"}`;
}

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
