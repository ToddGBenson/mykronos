/**
 * Words for an observed fact that contradicts a declared exposure
 * (TheHub #60826, `surfaces.CONTRADICTED_BY`).
 *
 * The declaration stays what the person said; the row shows the observation
 * beside it rather than resolving one into the other.
 */

export type SurfaceContradiction = {
  source: string;
  assertion: string;
  subject: string;
  vantage: string;
  tool: string;
  collector: string;
  collected_at: string;
  detail: string;
};

const ASSERTION_WORDS: Record<string, string> = {
  ingress_published: "a tunnel publishes",
  port_published: "a port answers at",
};

const VANTAGE_WORDS: Record<string, string> = {
  internet: "from the internet",
  lan: "from the LAN",
  host: "on the host",
};

/** One line per observation: what was seen, where from, and when. */
export function contradictionLine(c: SurfaceContradiction): string {
  const what = ASSERTION_WORDS[c.assertion] ?? c.assertion;
  const where = VANTAGE_WORDS[c.vantage] ?? c.vantage;
  const day = c.collected_at.slice(0, 10);
  return `${what} ${c.subject} (${where}, ${c.tool || "unknown tool"}, ${day})`;
}

/** The pill's hover text: the claim, and why it does not hold. */
export function contradictionTitle(
  exposure: string,
  contradictions: SurfaceContradiction[],
): string {
  if (contradictions.length === 0) return "";
  return (
    `Declared ${exposure}, but observed within 14 days: ` +
    contradictions.map(contradictionLine).join("; ")
  );
}
