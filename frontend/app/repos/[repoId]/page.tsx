import Link from "next/link";

import { CapabilityManager } from "@/components/capability-manager";
import { DecisionsTab } from "@/components/decisions";
import { InsiderRiskTab } from "@/components/insider-risk";
import { PipelinesPanel } from "@/components/pipelines";
import {
  OccurrenceDisposition,
  OpenFindings,
  type FindingsQuery,
} from "@/components/open-findings";
import { RemediationTab } from "@/components/remediation";
import { ScanHealthBoxes } from "@/components/scan-health";
import { SscsTab } from "@/components/sscs";
import {
  ALL_CAPABILITIES,
  Crumb,
  ErrorPanel,
  Pill,
  Section,
} from "@/components/primitives";
import type { ScanHealth } from "@/lib/api";
import {
  getCi,
  getDecisions,
  getFinding,
  getInsiderRisk,
  getOpenFindings,
  getRemediation,
  getRepo,
  getScanHealth,
  getSscs,
} from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * One dashboard, and then the views that are genuinely about something else.
 *
 * Findings, scan health, jobs and stages used to be three tabs and a panel,
 * which meant the four questions people actually ask together — what is
 * outstanding, is anything still scanning, is the pipeline green, and is every
 * stage covered — could not be answered without navigating. They are one
 * labelled page now. Risk decisions, supply chain, insider risk and
 * remediation stay behind tabs: each is a different subject with its own
 * vocabulary, not another view of the same findings.
 */
const TABS = [
  { id: "dashboard", label: "Dashboard" },
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
  searchParams: Promise<FindingsQuery>;
}) {
  const { repoId } = await params;
  const query = await searchParams;
  const tab = query.tab ?? "dashboard";

  const repo = await getRepo(repoId);
  if (!repo.ok) {
    return <ErrorPanel title="Repository unavailable" detail={repo.error} />;
  }

  // What "enabled" means depends on who scans this repo: the installer's
  // ledger for Actions, the grants for everything else — same union the
  // portfolio and stages views apply. `live` is which of those have actually
  // reported a run, so the manager can say implemented-and-reporting versus
  // implemented-and-silent.
  const scanHealth = await getScanHealth(repoId);
  const enabledSet = new Set(repo.data.enabled_capabilities);
  if (repo.data.scanned_by !== "github_actions") {
    for (const capability of repo.data.granted_capabilities ?? []) {
      enabledSet.add(capability);
    }
  }
  const live = scanHealth.ok
    ? scanHealth.data.capabilities
        .filter((entry) => entry.runs > 0)
        .map((entry) => entry.capability)
    : [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-baseline gap-3">
        <Crumb href="/">Portfolio</Crumb>
        <span className="text-ink-3">/</span>
        <h1 className="font-mono text-base font-bold">{repo.data.github_repo_full_name}</h1>
        <Pill tone={repo.data.status === "active" ? "pass" : "warn"}>
          {repo.data.status.replace("_", " ")}
        </Pill>
      </div>

      <CapabilityManager
        repoId={repoId}
        enabled={[...enabledSet].sort()}
        pending={repo.data.pending_capabilities ?? []}
        live={live}
      />

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

      <nav className="flex flex-wrap border-b-2 border-ink-2" aria-label="Repository views">
        {TABS.map((entry) => (
          <Link
            key={entry.id}
            href={
              entry.id === "dashboard"
                ? `/repos/${repoId}`
                : `/repos/${repoId}?tab=${entry.id}`
            }
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

      {tab === "decisions" ? (
        <RiskDecisionsTab repoId={repoId} />
      ) : tab === "sscs" ? (
        <SupplyChainTab repoId={repoId} />
      ) : tab === "insider" ? (
        <AegisTab repoId={repoId} />
      ) : tab === "remediation" ? (
        <PatchworkTab repoId={repoId} />
      ) : (
        <Dashboard
          repoId={repoId}
          query={query}
          enabled={[...enabledSet].sort()}
          scanHealth={scanHealth.ok ? scanHealth.data : null}
          scanHealthError={scanHealth.ok ? null : scanHealth.error}
        />
      )}
    </div>
  );
}

/** Findings, scan health, jobs and stages — the four questions, one page. */
async function Dashboard({
  repoId,
  query,
  enabled,
  scanHealth,
  scanHealthError,
}: {
  repoId: string;
  query: FindingsQuery;
  enabled: string[];
  scanHealth: ScanHealth | null;
  scanHealthError: string | null;
}) {
  const [findings, ci] = await Promise.all([
    getOpenFindings(repoId, {
      severity: query.severity,
      capability: query.capability,
      finding_status: query.status,
    }),
    getCi(repoId),
  ]);

  // A box per enabled check, plus anything that has reported without being
  // enabled — which is worth seeing rather than hiding, because it means the
  // ledger and the pipeline disagree.
  const reported = (scanHealth?.capabilities ?? []).map((row) => row.capability);
  const boxes = ALL_CAPABILITIES.filter(
    (capability) => enabled.includes(capability) || reported.includes(capability),
  ) as string[];
  for (const capability of reported) {
    if (!boxes.includes(capability)) boxes.push(capability);
  }

  return (
    <div className="flex flex-col gap-4">
      <Section
        title="Scan health"
        detail="how many of each check's runs succeeded"
        aside={
          scanHealth ? (
            <span className="font-mono text-[10px] text-ink-3">
              {reported.length} of {boxes.length} checks have ever run
            </span>
          ) : null
        }
      >
        {scanHealthError ? (
          <p className="px-3 py-2 text-[11px] text-critical">{scanHealthError}</p>
        ) : (
          <ScanHealthBoxes capabilities={boxes} health={scanHealth?.capabilities ?? []} />
        )}
      </Section>

      {ci.ok ? (
        <PipelinesPanel ci={ci.data} />
      ) : (
        // Said rather than dropped. These are two labelled sections of the
        // dashboard now, and a section that quietly disappears when its fetch
        // fails reads as a repository with no pipeline.
        <Section title="Pipeline stages and jobs" detail="unavailable">
          <p className="px-3 py-2 text-[11px] text-critical">{ci.error}</p>
        </Section>
      )}

      <Section
        title="Open findings"
        detail="triaged, deduplicated, and correlated into toxic combinations"
      >
        <div className="px-3 py-3">
          {findings.ok ? (
            <OpenFindings
              repoId={repoId}
              page={findings.data}
              query={query}
              detail={
                query.finding ? (
                  <FindingDisposition findingId={query.finding} />
                ) : undefined
              }
            />
          ) : (
            <ErrorPanel title="Findings unavailable" detail={findings.error} />
          )}
        </div>
      </Section>
    </div>
  );
}

/**
 * The disposition form for one occurrence.
 *
 * Fetched by id rather than looked up in a page of the flat list: the row a
 * person clicked is routinely not in the first hundred findings once
 * occurrences are grouped.
 */
async function FindingDisposition({ findingId }: { findingId: string }) {
  const result = await getFinding(findingId);
  if (!result.ok) {
    return (
      <p className="border-t border-rule pt-2 text-[10px] text-critical">
        {result.error}
      </p>
    );
  }
  return (
    <div className="flex flex-col gap-2">
      {result.data.code_snippet ? (
        <pre className="scroll-x max-h-40 border border-rule bg-paper p-2 font-mono text-[10px] leading-relaxed">
          {result.data.code_snippet}
        </pre>
      ) : null}
      {result.data.fingerprint_version === "v1-line" ? (
        <p className="border-l-2 border-high bg-high-wash px-2 py-1 text-[10px] text-ink-2">
          This finding&rsquo;s identity is positional — the adapter captured no
          code snippet, so it will churn when unrelated lines shift above it,
          and its age is unreliable.
        </p>
      ) : null}
      <OccurrenceDisposition findingId={findingId} status={result.data.status} />
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
