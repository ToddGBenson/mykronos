import { Pill } from "@/components/primitives";
import { type DeployLag, prodLagBadge } from "@/lib/prod-lag";

/**
 * "prod N behind" (#452), wherever a repository's deployment is shown.
 * Renders nothing for a repository with no deployment probe.
 */
export function ProdLag({ lag }: { lag: DeployLag | null | undefined }) {
  const badge = prodLagBadge(lag);
  if (!badge) return null;
  return (
    <Pill tone={badge.tone} title={badge.title}>
      {badge.label}
    </Pill>
  );
}
