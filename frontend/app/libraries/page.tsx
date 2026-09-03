import Link from "next/link";

import { getLibraries } from "@/lib/server";
import { ErrorPanel, Label, Pill, StatTile } from "@/components/primitives";

export const dynamic = "force-dynamic";

export const metadata = { title: "Libraries — Mykronos" };

const ECOSYSTEMS = ["npm", "pypi", "github", "unknown"];

/**
 * Every library the estate carries, and where.
 *
 * The per-repository supply-chain tab answers "what does this service depend
 * on". This answers the question one level up, which nothing else could: how
 * many distinct libraries are we maintaining, and which are we carrying at
 * more than one version?
 *
 * Ordered by reach, then divergence, because those are the two reasons to act
 * — and deliberately not filtered to vulnerable packages, since the point is
 * to reduce the dependency surface *before* one of them becomes a finding.
 */
export default async function LibrariesPage({
  searchParams,
}: {
  searchParams: Promise<{ ecosystem?: string }>;
}) {
  const { ecosystem } = await searchParams;
  const result = await getLibraries(ecosystem);

  if (!result.ok) {
    return <ErrorPanel title="Libraries unavailable" detail={result.error} />;
  }

  const data = result.data;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Libraries</h1>
        <span className="font-mono text-[13px] text-ink-3">
          {data.total_libraries} distinct across {data.repos_covered} repositor
          {data.repos_covered === 1 ? "y" : "ies"}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <StatTile label="Distinct libraries" value={data.total_libraries} />
        <StatTile
          label="In more than one repo"
          value={data.shared}
          sub="one advisory, estate-wide"
        />
        <StatTile
          label="At more than one version"
          value={data.divergent}
          sub="standardisation targets"
          alert={data.divergent > 0}
        />
        <StatTile label="Used once" value={data.single_use} sub="candidates to drop" />
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <Label>Ecosystem</Label>
        <Link
          href="/libraries"
          className={`border px-2 py-0.5 font-mono text-[12px] ${
            !ecosystem ? "border-accent text-accent" : "border-rule text-ink-3 hover:border-accent"
          }`}
        >
          all
        </Link>
        {ECOSYSTEMS.map((eco) => (
          <Link
            key={eco}
            href={ecosystem === eco ? "/libraries" : `/libraries?ecosystem=${eco}`}
            className={`border px-2 py-0.5 font-mono text-[12px] ${
              ecosystem === eco
                ? "border-accent text-accent"
                : "border-rule text-ink-3 hover:border-accent"
            }`}
          >
            {eco}
          </Link>
        ))}
      </div>

      {data.libraries.length === 0 ? (
        <p className="max-w-prose border border-dashed border-rule bg-paper-2 px-3 py-4 text-[14px] text-ink-3">
          Nothing indexed yet. A repository appears here after its next
          dependency scan archives an SBOM — it is absent rather than clean.
        </p>
      ) : (
        <div className="scroll-x border border-rule">
          <table className="w-full min-w-[720px] border-collapse bg-paper-2 text-[13px]">
            <thead>
              <tr className="border-b-2 border-ink-2 text-left">
                {["Library", "Ecosystem", "Repositories", "Versions"].map((heading) => (
                  <th
                    key={heading}
                    className="whitespace-nowrap px-2 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3"
                  >
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.libraries.map((lib) => (
                <tr
                  key={`${lib.ecosystem}:${lib.package_name}`}
                  className="border-b border-rule-soft last:border-b-0 hover:bg-paper-3"
                >
                  <td className="px-2 py-1.5">
                    <span className="font-mono">{lib.package_name}</span>
                    {lib.direct_anywhere ? (
                      <span className="ml-2">
                        <Pill tone="muted">direct</Pill>
                      </span>
                    ) : null}
                  </td>
                  <td className="px-2 py-1.5 font-mono text-ink-3">{lib.ecosystem}</td>
                  <td className="px-2 py-1.5 text-ink-2">
                    {lib.repos.length > 1 ? (
                      <span className="font-semibold">{lib.repos.length}</span>
                    ) : (
                      lib.repos.length
                    )}
                    <span className="ml-2 font-mono text-[12px] text-ink-3">
                      {lib.repos.join(", ")}
                    </span>
                  </td>
                  <td className="px-2 py-1.5">
                    {lib.divergent ? (
                      <span className="text-high">
                        {lib.versions.length} —{" "}
                        <span className="font-mono text-[12px]">
                          {lib.versions.join(", ")}
                        </span>
                      </span>
                    ) : (
                      <span className="font-mono text-[12px] text-ink-3">
                        {lib.versions[0] ?? "—"}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* The honest limit of this view, on the view rather than in a document,
          because it changes what somebody should conclude from a short list. */}
      <p className="max-w-prose text-[14px] leading-relaxed text-ink-3">{data.note}</p>
    </div>
  );
}
