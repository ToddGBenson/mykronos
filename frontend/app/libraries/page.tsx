import Link from "next/link";

import { getLibraries, getLibraryRequests, getManagedLibraries } from "@/lib/server";
import { ErrorPanel, Label, Pill, StatTile } from "@/components/primitives";
import { VettingChecks } from "@/components/library-request-form";
import type { LibraryRequestList, ManagedLibraries, ManagedLibrary } from "@/lib/api";

const STATUS_TONE = { approved: "pass", tolerated: "muted", banned: "critical" } as const;

/** The flags a library carries, as words; `null` (no data) is shown as unknown. */
function flagWords(flags: ManagedLibrary["flags"]): { word: string; on: boolean | null }[] {
  return [
    { word: "divergent", on: flags.divergent },
    { word: "EOL", on: flags.eol },
    { word: "abandoned", on: flags.abandoned },
    { word: "license changed", on: flags.license_changed },
    { word: "outside policy", on: flags.version_policy_violation },
    { word: "banned in use", on: flags.banned_in_use },
  ];
}

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
  const [result, managed, requests] = await Promise.all([
    getLibraries(ecosystem),
    getManagedLibraries(ecosystem),
    getLibraryRequests(),
  ]);

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
        <Link
          href="/libraries/request"
          className="ml-auto border border-accent px-2 py-0.5 font-mono text-[12px] text-accent hover:bg-paper-3"
        >
          Request a library
        </Link>
      </div>

      {managed.ok ? (
        <ManagedSection data={managed.data} />
      ) : (
        <ErrorPanel title="Library status unavailable" detail={managed.error} />
      )}
      {requests.ok ? <RequestsSection data={requests.data} /> : null}

      <Label as="h2">Inventory</Label>

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

/**
 * Every library in use with a status, an owner, a version policy and flags
 * (TheHub #60897). A status nobody recorded is shown as the default it is.
 */
function ManagedSection({ data }: { data: ManagedLibraries }) {
  return (
    <section className="flex flex-col gap-3">
      <Label as="h2">Status and ownership</Label>
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-5">
        <StatTile label="Approved" value={data.by_status.approved ?? 0} />
        <StatTile label="Tolerated" value={data.by_status.tolerated ?? 0} />
        <StatTile label="Banned" value={data.by_status.banned ?? 0} alert={(data.by_status.banned ?? 0) > 0} />
        <StatTile label="Unrecorded" value={data.unrecorded} sub="status is the default" />
        <StatTile label="Flagged" value={data.flagged} alert={data.flagged > 0} />
      </div>
      {data.libraries.length === 0 ? null : (
        <div className="scroll-x border border-rule">
          <table className="w-full min-w-[720px] border-collapse bg-paper-2 text-[13px]">
            <thead>
              <tr className="border-b-2 border-ink-2 text-left">
                {["Library", "Status", "Owner", "Version policy", "Flags"].map((heading) => (
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
                    <span className="ml-2 font-mono text-[12px] text-ink-3">{lib.ecosystem}</span>
                  </td>
                  <td className="px-2 py-1.5">
                    <Pill
                      tone={STATUS_TONE[lib.status as keyof typeof STATUS_TONE] ?? "muted"}
                      title={`set by: ${lib.status_source}`}
                    >
                      {lib.status}
                    </Pill>
                    {lib.status_source === "default" ? (
                      <span className="ml-2 text-[12px] text-ink-3">unrecorded</span>
                    ) : null}
                  </td>
                  <td className="px-2 py-1.5 text-ink-2">
                    {lib.owner || <span className="text-ink-3">no owner</span>}
                  </td>
                  <td className="px-2 py-1.5 font-mono text-[12px] text-ink-3">
                    {lib.version_policy} {lib.version_ref}
                  </td>
                  <td className="px-2 py-1.5">
                    <div className="flex flex-wrap gap-1">
                      {flagWords(lib.flags)
                        .filter((f) => f.on !== false)
                        .map((f) =>
                          f.on ? (
                            <Pill key={f.word} tone="warn">
                              {f.word}
                            </Pill>
                          ) : (
                            <span key={f.word} className="text-[11px] text-ink-3">
                              {f.word}?
                            </span>
                          ),
                        )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="max-w-prose text-[12px] text-ink-3">
        A flag with a question mark has no data yet: EOL and abandonment come from the
        registry, read daily. Unknown is not clean.
      </p>
    </section>
  );
}

/** Library requests and their outcomes; a rejection shows its reason (TheHub #60896). */
function RequestsSection({ data }: { data: LibraryRequestList }) {
  if (data.requests.length === 0) return null;
  return (
    <section className="flex flex-col gap-2">
      <Label as="h2">Requests</Label>
      <ul className="flex flex-col divide-y divide-rule-soft border border-rule bg-paper-2">
        {data.requests.slice(0, 25).map((req) => (
          <li key={req.id} className="flex flex-col gap-1 px-3 py-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono">
                {req.ecosystem} {req.package_name}@{req.version}
              </span>
              <Pill tone={req.tier === "clean" ? "pass" : "warn"}>{req.tier}</Pill>
              <Pill
                tone={
                  req.state === "approved"
                    ? "pass"
                    : req.state === "rejected"
                      ? "critical"
                      : "muted"
                }
              >
                {req.state.replaceAll("_", " ")}
              </Pill>
              <span className="text-[12px] text-ink-3">by {req.requested_by}</span>
            </div>
            {req.decision_reason ? (
              <p className="text-[13px] text-ink-2">
                {req.decided_by}: {req.decision_reason}
              </p>
            ) : null}
            <VettingChecks vetting={req.vetting} />
          </li>
        ))}
      </ul>
    </section>
  );
}
