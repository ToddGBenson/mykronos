import { EmptyState, Label, Pill } from "@/components/primitives";
import type { SupplyChainPackages } from "@/lib/api";

/**
 * Which packages are vulnerable, and which of them you can act on (B-027).
 *
 * The tab above this reported a trust score, advisory counts by severity, and
 * an SBOM you could download. It never named a package. "234 container
 * advisories" is a fact nobody can act on.
 *
 * **The fixable ones come first and are counted separately.** On this estate
 * 218 of 221 advisories have no published fix — the packages are already at
 * the newest version their distribution ships, and the vulnerability is
 * unpatched upstream. A view that lists them all together sends somebody to
 * bump versions that do not exist, which is exactly what the old standing
 * advice for this class did.
 *
 * Ordering is known-exploited, then fixable, then severity, then volume.
 * Sorting on advisory count would put eighteen unfixable libc6 rows above one
 * exploited-in-the-wild package with a patch waiting.
 */
export function VulnerablePackages({ data }: { data: SupplyChainPackages }) {
  if (data.total === 0) {
    return (
      <EmptyState
        title="No vulnerable packages"
        detail="No open advisory names a package for this repository. That is a real answer, not a missing scan — the Scan health panel says whether the lanes have run."
      />
    );
  }

  return (
    <section className="flex flex-col gap-2">
      <div className="flex flex-wrap items-baseline gap-3">
        <Label>Vulnerable packages</Label>
        <span className="font-mono text-[10px] text-ink-3">
          {data.total} package{data.total === 1 ? "" : "s"} · {data.advisories}{" "}
          advisor{data.advisories === 1 ? "y" : "ies"}
        </span>
        {data.kev_packages > 0 ? (
          <Pill tone="critical">{data.kev_packages} known exploited</Pill>
        ) : null}
        <Pill tone={data.fixable > 0 ? "warn" : "muted"}>
          {data.fixable} upgradable
        </Pill>
      </div>

      {data.unfixable_advisories > 0 ? (
        <p className="max-w-prose border-l-2 border-rule bg-paper-2 px-3 py-2 text-[10px] leading-relaxed text-ink-2">
          <strong className="text-ink">
            {data.unfixable_advisories} of {data.advisories} advisories have no
            published fix.
          </strong>{" "}
          There is no version to upgrade to, so a rebuild closes none of them —
          the package is already the newest its distribution ships and the
          vulnerability is unpatched upstream. Accept those with{" "}
          <span className="font-mono">no_vendor_fix</span> and a review date,
          which re-opens automatically the day a fix lands.
        </p>
      ) : null}

      <div className="scroll-x">
        <table className="w-full min-w-[720px] border-collapse font-mono text-[10px]">
          <thead>
            <tr className="text-left text-ink-3">
              <th className="px-2 py-1 font-normal">Package</th>
              <th className="px-2 py-1 font-normal">Installed</th>
              <th className="px-2 py-1 text-right font-normal">Advisories</th>
              <th className="px-2 py-1 font-normal">Worst</th>
              <th className="px-2 py-1 font-normal">Upgrade to</th>
              <th className="px-2 py-1 font-normal">In tree</th>
            </tr>
          </thead>
          <tbody>
            {data.packages.map((pkg) => (
              <tr
                key={`${pkg.ecosystem}:${pkg.package_name}`}
                className="border-t border-rule align-top"
              >
                <td className="px-2 py-1 text-ink">
                  {pkg.package_name}
                  {pkg.kev_count > 0 ? (
                    <span
                      className="ml-1.5 text-[8px] uppercase tracking-wide text-critical"
                      title="Listed in CISA's Known Exploited Vulnerabilities catalogue — a fact, not a prediction"
                    >
                      KEV
                    </span>
                  ) : null}
                  {pkg.cves.length > 0 ? (
                    <div className="mt-0.5 max-w-[36ch] text-[8px] leading-snug text-ink-3">
                      {pkg.cves.join(", ")}
                    </div>
                  ) : null}
                </td>
                <td className="px-2 py-1 text-ink-2">{pkg.installed_version || "—"}</td>
                <td className="px-2 py-1 text-right tabular-nums text-ink-2">
                  {pkg.advisories}
                </td>
                <td className="px-2 py-1 text-ink-2">{pkg.worst_severity}</td>
                <td className="px-2 py-1">
                  {pkg.fixable ? (
                    <span className="text-pass">{pkg.fixed_version}</span>
                  ) : (
                    <span className="text-ink-3">no published fix</span>
                  )}
                </td>
                {/* Three-valued, and the third value is the common one: most
                    SBOMs do not distinguish direct from transitive, and
                    rendering that as "transitive" would be a claim the
                    platform cannot make. */}
                <td className="px-2 py-1 text-ink-3">
                  {pkg.direct === null
                    ? "not stated"
                    : pkg.direct
                      ? "direct"
                      : "transitive"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
