import Link from "next/link";

import { DecisionsTab } from "@/components/decisions";
import { DispositionForm } from "@/components/disposition";
import { InsiderRiskTab } from "@/components/insider-risk";
import { RemediationTab } from "@/components/remediation";
import { SscsTab } from "@/components/sscs";
import {
  CapabilityDots,
  Crumb,
  EmptyState,
  ErrorPanel,
  Label,
  Pill,
  RelativeTime,
  SeverityText,
} from "@/components/primitives";
import type { Finding, Severity } from "@/lib/api";
import {
  getDecisions,
  getFindings,
  getInsiderRisk,
  getRemediation,
  getRepo,
  getScanHealth,
  getSscs,
} from "@/lib/server";

export const dynamic = "force-dynamic";

const TABS = [
  { id: "findings", label: "Findings" },
  { id: "scan-health", label: "Scan health" },
  { id: "decisions", label: "Risk decisions" },
  { id: "sscs", label: "Supply chain" },
  { id: "insider", label: "Insider risk" },
  { id: "remediation", label: "Remediation" },
] as const;

export default async function RepoPage({
  params,
  searchParams,
}: {
  params: Promise<{ repoId: string }>;
  searchParams: Promise<{ tab?: string; severity?: string; capability?: string; finding?: string }>;
}) {
  const { repoId } = await params;
  const query = await searchParams;
  const tab = query.tab ?? "findings";

  const repo = await getRepo(repoId);
  if (!repo.ok) {
    return <ErrorPanel title="Repository unavailable" detail={repo.error} />;
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-baseline gap-3">
        <Crumb href="/">Portfolio</Crumb>
        <span className="text-ink-3">/</span>
        <h1 className="font-mono text-base font-bold">{repo.data.github_repo_full_name}</h1>
        <Pill tone={repo.data.status === "active" ? "pass" : "warn"}>
          {repo.data.status.replace("_", " ")}
        </Pill>
        <span className="ml-auto">
          <CapabilityDots
            enabled={repo.data.enabled_capabilities}
            pending={repo.data.pending_capabilities ?? []}
          />
        </span>
      </div>

      {repo.data.pending_capabilities?.length ? (
        <div className="border border-high bg-high-wash px-3 py-2 text-[11px] text-ink-2">
          <strong className="text-high">Awaiting merge.</strong>{" "}
          {repo.data.pending_capabilities.join(", ")} will start running once
          pull request{" "}
          {repo.data.pending_pr_number ? `#${repo.data.pending_pr_number}` : ""} is
          merged. Ingestion is already permitted for them, so a workflow merged
          from that PR can post results immediately.
        </div>
      ) : null}

      {/* Every tab is built as of Phase 6 — the "arrives in Phase N" branch
          that used to live here has no subject left. */}
      <nav className="flex flex-wrap border-b-2 border-ink-2" aria-label="Repository views">
        {TABS.map((entry) => (
          <Link
            key={entry.id}
            href={`/repos/${repoId}?tab=${entry.id}`}
            className={`-mb-0.5 border-b-2 px-3 py-1.5 font-mono text-[10px] ${
              tab === entry.id
                ? "border-accent font-bold text-ink"
                : "border-transparent text-ink-3 hover:text-accent"
            }`}
          >
            {entry.label}
          </Link>
        ))}
      </nav>

      {tab === "scan-health" ? (
        <ScanHealthTab repoId={repoId} />
      ) : tab === "decisions" ? (
        <RiskDecisionsTab repoId={repoId} />
      ) : tab === "sscs" ? (
        <SupplyChainTab repoId={repoId} />
      ) : tab === "insider" ? (
        <AegisTab repoId={repoId} />
      ) : tab === "remediation" ? (
        <PatchworkTab repoId={repoId} />
      ) : (
        <FindingsTab repoId={repoId} query={query} />
      )}
    </div>
  );
}

async function FindingsTab({
  repoId,
  query,
}: {
  repoId: string;
  query: { severity?: string; capability?: string; finding?: string };
}) {
  const result = await getFindings(repoId, {
    severity: query.severity,
    capability: query.capability,
  });
  if (!result.ok) return <ErrorPanel title="Findings unavailable" detail={result.error} />;

  const { findings, total, raw_output_included } = result.data;
  const selected = query.finding
    ? findings.find((f) => f.finding_id === query.finding)
    : undefined;

  const filterHref = (patch: Record<string, string | undefined>) => {
    const next = new URLSearchParams();
    next.set("tab", "findings");
    for (const [key, value] of Object.entries({ ...query, ...patch })) {
      if (value) next.set(key, value);
    }
    return `/repos/${repoId}?${next.toString()}`;
  };

  if (total === 0) {
    return (
      <EmptyState
        title="No findings"
        detail={
          query.severity || query.capability
            ? "Nothing matches these filters. Clear them to see everything."
            : "Either nothing has been found, or nothing has scanned yet — check the Scan health tab to tell which."
        }
      />
    );
  }

  return (
    <div className="flex flex-col gap-3 lg:flex-row">
      <div className="min-w-0 flex-1">
        <div className="mb-2 flex flex-wrap items-center gap-1.5">
          <Label>Severity</Label>
          {(["critical", "high", "medium", "low", "info"] as Severity[]).map((severity) => (
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
          <span className="ml-auto font-mono text-[10px] text-ink-3">
            {findings.length} of {total}
          </span>
        </div>

        <div className="scroll-x border border-rule">
          <table className="w-full min-w-[600px] border-collapse bg-paper-2 font-mono text-[11px]">
            <thead>
              <tr className="border-b-2 border-ink-2 text-left">
                {["Sev", "Rule", "Location", "Cap", "First seen"].map((heading) => (
                  <th
                    key={heading}
                    className="whitespace-nowrap px-2 py-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-ink-3"
                  >
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr
                  key={finding.finding_id}
                  className={`border-b border-rule-soft last:border-b-0 hover:bg-paper-3 ${
                    selected?.finding_id === finding.finding_id ? "bg-accent-wash" : ""
                  }`}
                >
                  <td className="px-2 py-2">
                    <SeverityText severity={finding.severity} />
                  </td>
                  <td className="px-2 py-2">
                    <Link
                      href={filterHref({ finding: finding.finding_id })}
                      className="text-ink hover:text-accent"
                    >
                      {finding.rule_id}
                    </Link>
                    {finding.status !== "open" ? (
                      <span className="ml-2">
                        <Pill tone="muted">{finding.status.replace("_", " ")}</Pill>
                      </span>
                    ) : null}
                  </td>
                  <td className="max-w-[24ch] truncate px-2 py-2 text-ink-2">
                    {finding.package_name
                      ? `${finding.package_name}@${finding.package_version ?? "?"}`
                      : (finding.file_path ?? "—")}
                    {finding.line_start ? `:${finding.line_start}` : ""}
                  </td>
                  <td className="px-2 py-2 text-ink-3">{finding.capability}</td>
                  <td className="whitespace-nowrap px-2 py-2 text-ink-3">
                    <RelativeTime value={finding.first_seen_at} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <aside className="w-full shrink-0 lg:w-[26rem]">
        {selected ? (
          <FindingDetail finding={selected} rawIncluded={raw_output_included} />
        ) : (
          <div className="border border-dashed border-rule bg-paper-2 p-4 text-[11px] text-ink-3">
            Select a finding to see its detail and record a disposition.
          </div>
        )}
      </aside>
    </div>
  );
}

function FindingDetail({
  finding,
  rawIncluded,
}: {
  finding: Finding;
  rawIncluded: boolean;
}) {
  return (
    <div className="flex flex-col gap-3 border border-rule bg-paper-2 p-3">
      <div>
        <SeverityText severity={finding.severity} />
        <h2 className="mt-1 text-sm font-semibold leading-snug">{finding.title}</h2>
        <p className="mt-1 font-mono text-[10px] text-ink-3">
          {finding.rule_id} · {finding.capability}
          {finding.cvss_score ? ` · CVSS ${finding.cvss_score}` : ""}
        </p>
      </div>

      {finding.description ? (
        <p className="max-h-40 overflow-y-auto whitespace-pre-wrap text-[11px] leading-relaxed text-ink-2">
          {finding.description}
        </p>
      ) : null}

      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-[10px]">
        {[
          ["Location", finding.file_path ?? finding.package_name ?? "—"],
          ["Symbol", finding.symbol ?? "—"],
          ["Status", finding.status],
          ["Identity", finding.fingerprint_version ?? "—"],
        ].map(([term, value]) => (
          <div key={term} className="contents">
            <dt className="text-ink-3">{term}</dt>
            <dd className="truncate text-ink-2">{value}</dd>
          </div>
        ))}
      </dl>

      {finding.fingerprint_version === "v1-line" ? (
        <p className="border-l-2 border-high bg-high-wash px-2 py-1 text-[10px] text-ink-2">
          This finding&rsquo;s identity is positional — the adapter captured no
          code snippet, so it will churn when unrelated lines shift above it,
          and its age is unreliable.
        </p>
      ) : null}

      {rawIncluded && finding.code_snippet ? (
        <div>
          <Label>Snippet</Label>
          <pre className="scroll-x mt-1 max-h-40 border border-rule bg-paper p-2 font-mono text-[10px] leading-relaxed">
            {finding.code_snippet}
          </pre>
        </div>
      ) : !rawIncluded ? (
        <p className="text-[10px] text-ink-3">
          Raw tool output is withheld from viewer roles — a secrets finding
          necessarily quotes context around the secret.
        </p>
      ) : null}

      <div className="border-t border-rule pt-3">
        <Label>Disposition</Label>
        <div className="mt-2">
          <DispositionForm
            findingId={finding.finding_id}
            currentStatus={finding.status}
          />
        </div>
      </div>
    </div>
  );
}

async function RiskDecisionsTab({ repoId }: { repoId: string }) {
  const result = await getDecisions(repoId);
  if (!result.ok) {
    return <ErrorPanel title="Decisions unavailable" detail={result.error} />;
  }
  return (
    <DecisionsTab
      repoFullName={result.data.repo_full_name}
      decisions={result.data.decisions}
    />
  );
}

async function SupplyChainTab({ repoId }: { repoId: string }) {
  const result = await getSscs(repoId);
  if (!result.ok) {
    return <ErrorPanel title="Supply-chain evidence unavailable" detail={result.error} />;
  }
  return (
    <SscsTab
      evidence={result.data.evidence}
      latest={result.data.latest ?? null}
    />
  );
}

async function AegisTab({ repoId }: { repoId: string }) {
  const result = await getInsiderRisk(repoId);
  if (!result.ok) {
    return <ErrorPanel title="Insider risk unavailable" detail={result.error} />;
  }
  return (
    <InsiderRiskTab
      repoFullName={result.data.repo_full_name}
      signals={result.data.signals}
      detailIncluded={result.data.detail_included}
      governance={result.data.governance}
    />
  );
}

async function PatchworkTab({ repoId }: { repoId: string }) {
  const result = await getRemediation(repoId);
  if (!result.ok) {
    return <ErrorPanel title="Remediation unavailable" detail={result.error} />;
  }
  return (
    <RemediationTab
      events={result.data.events}
      openDraftPrs={result.data.open_draft_prs}
      note={result.data.note}
    />
  );
}

async function ScanHealthTab({ repoId }: { repoId: string }) {
  const result = await getScanHealth(repoId);
  if (!result.ok) return <ErrorPanel title="Scan health unavailable" detail={result.error} />;

  if (result.data.capabilities.length === 0) {
    return (
      <EmptyState
        title="Nothing has scanned yet"
        // Not "once the install PR merges": a repo scanned by Concourse never
        // has one. The lake cannot tell which CI produced a run and must not
        // care (spec 15 §4), so neither should this sentence.
        detail="Every run a capability records — success, no-op or failure — appears here, whichever CI produced it."
      />
    );
  }

  return (
    <div className="scroll-x border border-rule">
      <table className="w-full min-w-[640px] border-collapse bg-paper-2 font-mono text-[11px]">
        <thead>
          <tr className="border-b-2 border-ink-2 text-left">
            {["Capability", "Runs", "Succeeded", "Failed", "No targets", "Failure rate", "Last run"].map(
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
          {result.data.capabilities.map((row) => (
            <tr key={row.capability} className="border-b border-rule-soft last:border-b-0">
              <td className="px-2 py-2 font-semibold">{row.capability}</td>
              <td className="tabular px-2 py-2">{row.runs}</td>
              <td className="tabular px-2 py-2 text-pass">{row.succeeded}</td>
              <td className={`tabular px-2 py-2 ${row.failed ? "text-critical" : ""}`}>
                {row.failed}
              </td>
              <td className="tabular px-2 py-2 text-ink-3" title="Scanned, nothing applicable to scan">
                {row.no_applicable_targets}
              </td>
              <td className={`tabular px-2 py-2 ${row.failure_rate > 0.2 ? "text-high" : ""}`}>
                {(row.failure_rate * 100).toFixed(0)}%
              </td>
              <td className="whitespace-nowrap px-2 py-2 text-ink-2">
                <RelativeTime value={row.last_run_at} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
