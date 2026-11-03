import type { ToxicChain } from "@/lib/api";

/** What each link in a chain is, in the words the page uses (TheHub #60894). */
const STEP_LABEL: Record<string, string> = {
  entry_point: "Way in",
  auth_weakness: "Authentication weakness",
  vulnerable_component: "Known-vulnerable component",
  injectable_sink: "Injectable sink",
};

export type ChainStep = {
  key: string;
  label: string;
  /** The finding, or the entry point, this link is. */
  subject: string;
  /** How the link was established: the declaration, or the selector and the reason. */
  detail: string;
};

/**
 * A chain as the steps a reader follows: the declared entry point first, then
 * each finding behind it with the selector that placed it there and why it
 * qualifies. The entry point says it was declared, because nothing observed it.
 */
export function chainSteps(chain: ToxicChain): ChainStep[] {
  return chain.links.map((link, index) => {
    const label = STEP_LABEL[link.step] ?? link.step;
    if (link.step === "entry_point") {
      const door = chain.entry_point;
      const where = door.declared_via === "manifest" ? "the threat-model file" : "the register";
      const evidence = door.evidence_ref ? `, evidence ${door.evidence_ref}` : "";
      return {
        key: `entry_point-${door.id}`,
        label,
        subject: door.name,
        detail: `declared ${door.exposure}-facing in ${where}${evidence}`,
      };
    }
    const parts = [link.located_by ? `behind it by ${link.located_by}` : "", link.qualifies ?? ""];
    return {
      key: link.finding_id ?? `link-${index}`,
      label,
      subject: [link.capability, link.severity, link.title].filter(Boolean).join(" · "),
      detail: parts.filter(Boolean).join("; "),
    };
  });
}
