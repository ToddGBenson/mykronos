import Link from "next/link";

import {
  EmptyState,
  ErrorPanel,
  Label,
  Pill,
  RelativeTime,
  SeverityText,
  StatTile,
  Verdict,
} from "@/components/primitives";
import { SEVERITY_ORDER, type Severity } from "@/lib/api";
import { getTriage } from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * The capabilities that produce *findings*, which is not the same list as
 * `ALL_CAPABILITIES`.
 *
 * `atlas` was missing, and it is the one that mattered: every SCA finding in
 * the lake is filed under it — osv-scanner uploads with `--capability atlas` —
 * so dependency vulnerabilities were the one class this queue could show but
 * never filter down to. Easy to miss because the capability is *named* after
 * the supply-chain product rather than after "dependencies".
 *
 * Deliberately absent: `aegis` records insider-risk signals, `patchwork`
 * opens pull requests, and `oracle` scores what the others found. None of the
 * three writes a Finding, so a filter for them would always come back empty —
 * which reads as "no insider risk" rather than "wrong question".
 */
const CAPABILITIES = ["sast", "dast", "secrets", "containers", "iac", "cloud", "atlas"];

export default async function TriagePage({
  searchParams,
}: {
  searchParams: Promise<{
    severity?: string;
    capability?: string;
    rule_id?: string;
    kev_only?: string;
    min_epss?: string;
  }>;
}) {
  const query = await searchParams;
  const result = await getTriage({
    severity: query.severity,
    capability: query.capability,
    rule_id: query.rule_id,
    kev_only: query.kev_only === "1",
    min_epss: query.min_epss ? Number(query.min_epss) : undefined,
  });

  if (!result.ok) {
    return <ErrorPanel title="Queue unavailable" detail={result.error} />;
  }

  const { items, open_by_severity, total_open, truncated } = result.data;

  const filterHref = (patch: Record<string, string | undefined>) => {
    const next = new URLSearchParams();
    for (const [key, value] of Object.entries({ ...query, ...patch })) {
      if (value) next.set(key, value);
    }
    const qs = next.toString();
    return qs ? `/triage?${qs}` : "/triage";
  };

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Triage queue</h1>
        <span className="font-mono text-[11px] text-ink-3">
          {total_open} open across the portfolio
        </span>
        <Link
          href="/"
          className="ml-auto border border-rule px-2 py-1 font-mono text-[10px] text-ink-3 hover:border-accent hover:text-accent"
        >
          portfolio view
        </Link>
      </div>

      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <StatTile
          label="Critical"
          value={open_by_severity.critical ?? 0}
          alert={(open_by_severity.critical ?? 0) > 0}
        />
        <StatTile label="High" value={open_by_severity.high ?? 0} />
        <StatTile label="Medium" value={open_by_severity.medium ?? 0} />
        <StatTile
          label="Low + info"
          value={(open_by_severity.low ?? 0) + (open_by_severity.info ?? 0)}
        />
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <Label>Severity</Label>
        {SEVERITY_ORDER.map((severity: Severity) => (
          <Link
            key={severity}
            href={filterHref({
              severity: query.severity === severity ? undefined : severity,
            })}
            className={`border px-1.5 py-0.5 font-mono text-[9px] ${
              query.severity === severity
                ? "border-accent bg-accent-wash text-accent"
                : "border-rule text-ink-3 hover:border-accent"
            }`}
          >
            {severity}
          </Link>
        ))}
        <span className="mx-2 h-3 w-px bg-rule" />
        <Label>Capability</Label>
        {CAPABILITIES.map((capability) => (
          <Link
            key={capability}
            href={filterHref({
              capability: query.capability === capability ? undefined : capability,
            })}
            className={`border px-1.5 py-0.5 font-mono text-[9px] ${
              query.capability === capability
                ? "border-accent bg-accent-wash text-accent"
                : "border-rule text-ink-3 hover:border-accent"
            }`}
          >
            {capability}
          </Link>
        ))}
      </div>

      {/* Same GET-form pattern as the per-repo Findings tab (spec 17 §3) —
          the query lives in the URL for every other filter here too. */}
      <form method="get" action="/triage" className="flex items-center gap-1.5">
        {query.severity ? <input type="hidden" name="severity" value={query.severity} /> : null}
        {query.capability ? (
          <input type="hidden" name="capability" value={query.capability} />
        ) : null}
        <Label>Rule / CVE</Label>
        <input
          type="search"
          name="rule_id"
          defaultValue={query.rule_id ?? ""}
          placeholder="e.g. CWE-89 or CVE-2024-…"
          className="border border-rule bg-paper px-1.5 py-0.5 font-mono text-[9px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
        />
        {query.rule_id ? (
          <Link
            href={filterHref({ rule_id: undefined })}
            className="border border-accent bg-accent-wash px-1.5 py-0.5 font-mono text-[9px] text-accent"
          >
            {query.rule_id} ✕
          </Link>
        ) : null}
      </form>

      <div className="flex flex-wrap items-center gap-1.5">
        <Label>Threat intel</Label>
        <Link
          href={filterHref({ kev_only: query.kev_only === "1" ? undefined : "1" })}
          className={`border px-1.5 py-0.5 font-mono text-[9px] ${
            query.kev_only === "1"
              ? "border-critical bg-critical-wash text-critical"
              : "border-rule text-ink-3 hover:border-accent"
          }`}
        >
          KEV only
        </Link>
        <Link
          href={filterHref({ min_epss: query.min_epss === "0.5" ? undefined : "0.5" })}
          className={`border px-1.5 py-0.5 font-mono text-[9px] ${
            query.min_epss === "0.5"
              ? "border-high bg-high-wash text-high"
              : "border-rule text-ink-3 hover:border-accent"
          }`}
        >
          EPSS ≥ 50%
        </Link>
      </div>

      {items.length === 0 ? (
        <EmptyState
          title={
            query.severity || query.capability || query.rule_id || query.kev_only || query.min_epss
              ? "Nothing matches these filters"
              : "Nothing open"
          }
          detail={
            query.severity || query.capability || query.rule_id || query.kev_only || query.min_epss ? (
              "Clear the filters to see the whole queue."
            ) : (
              <>
                Either every finding is resolved, or nothing has scanned yet.
                The portfolio view distinguishes the two — a repo awaiting its
                first scan is marked there rather than counted as clean here.
              </>
            )
          }
        />
      ) : (
        <div className="scroll-x border border-rule">
          <table className="w-full min-w-[880px] border-collapse bg-paper-2 font-mono text-[11px]">
            <thead>
              <tr className="border-b-2 border-ink-2 text-left">
                {["Sev", "Repository", "Verdict", "Rule", "Location", "Cap", "Age"].map(
                  (heading) => (
                    <th
                      key={heading}
                      className="whitespace-nowrap px-2 py-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-ink-3"
                    >
                      {heading}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr
                  key={item.finding_id}
                  className="border-b border-rule-soft last:border-b-0 hover:bg-paper-3"
                >
                  <td className="px-2 py-2">
                    <SeverityText severity={item.severity as Severity} />
                    {item.in_kev ? (
                      <span className="ml-1" title={`${item.cve_id} is in CISA's KEV catalog`}>
                        <Pill tone="critical">KEV</Pill>
                      </span>
                    ) : null}
                  </td>
                  <td className="max-w-[22ch] truncate px-2 py-2">
                    <Link
                      href={`/repos/${item.repo_id}`}
                      className="text-ink hover:text-accent"
                      title={item.repo_full_name}
                    >
                      {item.repo_full_name}
                    </Link>
                  </td>
                  <td className="px-2 py-2">
                    <Verdict recommendation={item.repo_recommendation} />
                  </td>
                  <td className="px-2 py-2">
                    <Link
                      href={`/repos/${item.repo_id}?tab=findings&finding=${item.finding_id}`}
                      className="font-semibold text-ink hover:text-accent"
                      title={item.title}
                    >
                      {item.rule_id}
                    </Link>
                  </td>
                  <td className="max-w-[26ch] truncate px-2 py-2 text-ink-2">
                    {item.package_name
                      ? `${item.package_name}@${item.package_version ?? "?"}`
                      : (item.file_path ?? "—")}
                    {item.line_start ? `:${item.line_start}` : ""}
                  </td>
                  <td className="px-2 py-2 text-ink-3">{item.capability}</td>
                  <td className="whitespace-nowrap px-2 py-2 text-ink-2">
                    <RelativeTime value={item.first_seen_at} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {truncated ? (
        <p className="border-l-2 border-high bg-high-wash px-3 py-2 text-[11px] text-ink-2">
          <strong className="text-high">Showing the first 100.</strong> There are{" "}
          {total_open} open findings in scope — narrow by severity or capability
          to see the rest.
        </p>
      ) : null}

      <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
        <Label>Reading this queue</Label>
        <br />
        Ordered by severity, then by <em>age</em> rather than recency: an old
        critical is worse than a new one, because it has been exploitable for
        longer and has already survived somebody deciding not to fix it. Only
        active repositories appear — a removed repo&rsquo;s findings are still in
        the lake and still on its own page, but a queue is a list of work.{" "}
        <Pill tone="muted">verdict</Pill> is the repository&rsquo;s standing
        Oracle score, carried here so the same critical can be read differently
        in a repo already called <span className="font-mono">no go</span>.
      </p>
    </div>
  );
}
