import Link from "next/link";

import { CapabilityManager } from "@/components/capability-manager";
import { DecisionsTab } from "@/components/decisions";
import { InsiderRiskTab } from "@/components/insider-risk";
import { PassRateSparkline } from "@/components/pass-rate-sparkline";
import { PipelineCoverage, PipelineLinks } from "@/components/pipelines";
import { ScanNowButton } from "@/components/scan-now";
import {
  OccurrenceDisposition,
  OpenFindings,
  type FindingsQuery,
} from "@/components/open-findings";
import { RemediationTab } from "@/components/remediation";
import { PathToGreen } from "@/components/path-to-green";
import { ReachabilityCard } from "@/components/reachability";
import { RiskProfileCard } from "@/components/risk-profile";
import { ScanHealthBoxes } from "@/components/scan-health";
import { SscsTab } from "@/components/sscs";
import { ThreatModelTab } from "@/components/threat-model";
import {
  ALL_CAPABILITIES,
  Crumb,
  ErrorPanel,
  Pill,
  Section,
} from "@/components/primitives";
import type { CiPage, ScanHealth } from "@/lib/api";
import {
  getCi,
  getDecisions,
  getFinding,
  getInsiderRisk,
  getOpenFindings,
  getRemediation,
  getRepo,
  getReachability,
  getRiskProfile,
  getScanHealth,
  getScanRunTrend,
  getSscs,
  getThreatModel,
} from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * Eight tabs, in this order (spec 18 §2).
 *
 * `Dashboard` is what spec 18's first pass called "Harness" — enable/disable,
 * scan health, enabled jobs — promoted to the default landing tab rather than
 * duplicated into a second one. It carries no findings; that is what the
 * Findings tab is for. `Harness` is now specifically a test-running tab
 * (`TestHarnessTab`) — unit/functional/QA execution, not general scan health.
 */
const TABS = [
  { id: "dashboard", label: "Dashboard" },
  { id: "findings", label: "Findings" },
  { id: "harness", label: "Harness" },
  { id: "threat-model", label: "Threat Model" },
  { id: "sscs", label: "Supply chain" },
  { id: "insider", label: "Insider Threat" },
  { id: "decisions", label: "Risk Decision" },
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

  // Fetched once per page load regardless of which tab is open: the
  // Built/Scanned-by links (spec 17 §2.3) render at the top of every tab, the
  // Harness tab's capability buttons (spec 17 §2.2) need the same `CiPage` to
  // colour themselves consistently with the panel below them, and Dashboard
  // (spec 18 §3) reuses both rather than issuing its own copies.
  const [scanHealth, ci] = await Promise.all([getScanHealth(repoId), getCi(repoId)]);
  // What "enabled" means depends on who scans this repo: the installer's
  // ledger for Actions, the grants for everything else — same union the
  // portfolio and stages views apply. `live` is which of those have actually
  // reported a run, so the manager can say implemented-and-reporting versus
  // implemented-and-silent.
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

      {ci.ok ? (
        <PipelineLinks ci={ci.data} />
      ) : (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[11px] text-critical">
          {ci.error}
        </p>
      )}

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
      ) : tab === "threat-model" ? (
        <ThreatModelTabPanel repoId={repoId} />
      ) : tab === "findings" ? (
        <FindingsTab repoId={repoId} query={query} />
      ) : tab === "harness" ? (
        <TestHarnessTab repoId={repoId} enabled={[...enabledSet].sort()} />
      ) : (
        <DashboardTab
          repoId={repoId}
          enabled={[...enabledSet].sort()}
          pending={repo.data.pending_capabilities ?? []}
          live={live}
          scanHealth={scanHealth.ok ? scanHealth.data : null}
          scanHealthError={scanHealth.ok ? null : scanHealth.error}
          ci={ci.ok ? ci.data : null}
        />
      )}
    </div>
  );
}

/**
 * The landing tab: is the harness running, and is it healthy —
 * enable/disable, scan health, enabled jobs. On correction: this was
 * originally split into "Harness" (this content) and a separately-composed
 * "Dashboard" that duplicated it plus a findings list. Dashboard *is* this
 * content now, not a second view of it — and carries no findings of its own;
 * that is the Findings tab's subject, not this one's. "Harness" is freed up
 * for actually running tests (`TestHarnessTab`, below).
 */
function DashboardTab({
  repoId,
  enabled,
  pending,
  live,
  scanHealth,
  scanHealthError,
  ci,
}: {
  repoId: string;
  enabled: string[];
  pending: string[];
  live: string[];
  scanHealth: ScanHealth | null;
  scanHealthError: string | null;
  ci: CiPage | null;
}) {
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
      <div className="flex flex-wrap items-start justify-between gap-3">
        <CapabilityManager
          repoId={repoId}
          enabled={enabled}
          pending={pending}
          live={live}
          ci={ci}
        />
        <ScanNowButton repoId={repoId} />
      </div>

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

      {ci ? (
        <PipelineCoverage ci={ci} />
      ) : (
        // Said rather than dropped. A section that quietly disappears when
        // its fetch fails reads as a repository with no pipeline.
        <Section title="Enabled jobs" detail="unavailable">
          <p className="px-3 py-2 text-[11px] text-critical">
            Pipeline state could not be read.
          </p>
        </Section>
      )}
    </div>
  );
}

/** Unit, functional, and QA-doc pass/fail lanes — a `ScanRun`, not a
 *  `Finding` (D-046): these produce a status and a count, never a security
 *  finding, so a failing test never enters Oracle's risk score. Reachable
 *  on-demand today for Concourse-scanned repos only — no GitHub Actions
 *  workflow template exists yet for any of the three, so an Actions-scanned
 *  repo cannot even enable them (`api/repos.py`'s `DISPATCHABLE_CAPABILITIES`
 *  comment has the full story). Said here rather than left to look broken. */
const TEST_CAPABILITIES = ["unit", "functional", "qa"] as const;

async function TestHarnessTab({
  repoId,
  enabled,
}: {
  repoId: string;
  enabled: string[];
}) {
  const scanHealth = await getScanHealth(repoId);
  const reported = scanHealth.ok
    ? scanHealth.data.capabilities.map((c) => c.capability)
    : [];
  const boxes = TEST_CAPABILITIES.filter(
    (capability) => enabled.includes(capability) || reported.includes(capability),
  );

  return (
    <div className="flex flex-col gap-4">
      <p className="max-w-prose border-l-2 border-rule bg-paper-2 px-3 py-2 text-[11px] leading-relaxed text-ink-2">
        <strong className="text-ink">Pass/fail, not findings.</strong> Unit,
        functional, and QA-doc checks record a run and a count, never a
        security finding — a failing test cannot lower this repository&rsquo;s
        risk score by being suppressed the way a finding can. &ldquo;Run
        tests&rdquo; reaches Concourse-scanned repositories today; no GitHub
        Actions workflow template exists yet for these three lanes, so an
        Actions-scanned repository cannot enable them here at all.
      </p>

      <div className="flex flex-wrap items-start justify-between gap-3">
        <span className="font-mono text-[10px] text-ink-3">
          {boxes.length === 0
            ? "None of unit, functional, or qa is enabled for this repository — enable one on the Dashboard tab."
            : `Enabled: ${boxes.join(", ")}`}
        </span>
        <ScanNowButton
          repoId={repoId}
          capabilities={[...TEST_CAPABILITIES]}
          label="run tests"
        />
      </div>

      <Section title="Test health" detail="pass/fail, most recent run">
        {scanHealth.ok ? (
          boxes.length > 0 ? (
            <ScanHealthBoxes capabilities={boxes} health={scanHealth.data.capabilities} />
          ) : (
            <p className="px-3 py-3 text-[11px] text-ink-3">
              Nothing to show until unit, functional, or qa is enabled.
            </p>
          )
        ) : (
          <p className="px-3 py-2 text-[11px] text-critical">{scanHealth.error}</p>
        )}
      </Section>

      {boxes.map((capability) => (
        <LaneTrend key={capability} repoId={repoId} capability={capability} />
      ))}
    </div>
  );
}

/** One lane's pass rate over time (spec 19 §1.1) — its own component so each
 *  lane's fetch is independent: a trend that fails to load for `qa` should
 *  not take `unit`'s down with it. */
async function LaneTrend({ repoId, capability }: { repoId: string; capability: string }) {
  const trend = await getScanRunTrend(repoId, capability);
  return (
    <Section title={`${capability} — pass rate`} detail="last 90 days">
      <div className="px-3 py-2">
        {trend.ok ? (
          <PassRateSparkline capability={capability} points={trend.data.points} />
        ) : (
          <p className="text-[11px] text-critical">{trend.error}</p>
        )}
      </div>
    </Section>
  );
}

/** What the harness found. Grouped, deduplicated, and correlated into toxic
 *  combinations — see `open-findings.tsx` for the query/grouping logic. */
async function FindingsTab({
  repoId,
  query,
}: {
  repoId: string;
  query: FindingsQuery;
}) {
  const findings = await getOpenFindings(repoId, {
    severity: query.severity,
    capability: query.capability,
    finding_status: query.status,
    rule_id: query.rule_id,
    kev_only: query.kev_only === "1",
    min_epss: query.min_epss ? Number(query.min_epss) : undefined,
    triage: query.triage,
    fixable: query.fixable === "1" ? true : undefined,
  });

  if (!findings.ok) {
    return <ErrorPanel title="Findings unavailable" detail={findings.error} />;
  }

  return (
    <OpenFindings
      repoId={repoId}
      page={findings.data}
      query={query}
      detail={
        query.finding ? <FindingDisposition findingId={query.finding} /> : undefined
      }
    />
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
  // The profile is one of the inputs the decisions below are computed from
  // (spec 21 §1.5), so it belongs beside the term breakdown that reads it —
  // not on a settings page somewhere else. Fetched alongside rather than
  // nested, so a profile that fails to load does not take the decisions with
  // it.
  const [result, profile, reachability] = await Promise.all([
    getDecisions(repoId),
    getRiskProfile(repoId),
    getReachability(repoId),
  ]);
  if (!result.ok) {
    return <ErrorPanel title="Decisions unavailable" detail={result.error} />;
  }
  // The newest decision carries the inverse of its own score (spec 26 §1).
  // Read from the decision rather than fetched separately: a path computed by
  // a second call could disagree with the score it is supposed to explain.
  const latest = result.data.decisions[0];
  const path =
    (latest?.inputs_snapshot as { path_to_green?: Parameters<typeof PathToGreen>[0]["path"] })
      ?.path_to_green ?? null;

  return (
    <div className="flex flex-col gap-4">
      <PathToGreen repoId={repoId} path={path} />
      {profile.ok ? (
        <RiskProfileCard repoId={repoId} profile={profile.data} />
      ) : (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[11px] text-critical">
          {profile.error}
        </p>
      )}
      {/* The other Oracle input recorded outside the score itself, and the
          only one that lowers it. Beside the profile for the same reason the
          profile is here: an input you cannot inspect is one people stop
          believing. A failure to load it does not take the decisions. */}
      {reachability.ok ? (
        <ReachabilityCard report={reachability.data} />
      ) : (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[11px] text-critical">
          {reachability.error}
        </p>
      )}
      <DecisionsTab
        repoFullName={result.data.repo_full_name}
        decisions={result.data.decisions}
      />
    </div>
  );
}

async function SupplyChainTab({ repoId }: { repoId: string }) {
  const result = await getSscs(repoId);
  if (!result.ok) {
    return <ErrorPanel title="Supply-chain evidence unavailable" detail={result.error} />;
  }
  return (
    <SscsTab
      repoId={repoId}
      evidence={result.data.evidence}
      latest={result.data.latest ?? null}
    />
  );
}

async function ThreatModelTabPanel({ repoId }: { repoId: string }) {
  const result = await getThreatModel(repoId);
  if (!result.ok) {
    return <ErrorPanel title="Threat model unavailable" detail={result.error} />;
  }
  return <ThreatModelTab repoId={repoId} page={result.data} />;
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
      blocking={result.data.blocking}
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
