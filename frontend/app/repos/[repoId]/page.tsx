import Link from "next/link";

import { CapabilityManager } from "@/components/capability-manager";
import { DecisionsTab } from "@/components/decisions";
import { InsiderRiskTab } from "@/components/insider-risk";
import { PassRateSparkline } from "@/components/pass-rate-sparkline";
import { TestCoverage } from "@/components/test-coverage";
import { JobLights, PipelineLinks, ReportingGaps } from "@/components/pipelines";
import { WorkflowSwitches } from "@/components/workflow-switches";
import { ScanNowButton } from "@/components/scan-now";
import {
  OccurrenceDisposition,
  OpenFindings,
  type FindingsQuery,
} from "@/components/open-findings";
import { RecommendedFixes } from "@/components/recommended-fixes";
import { RemediationTab } from "@/components/remediation";
import { RemediateToday } from "@/app/remediate/page";
import { AgeForecast } from "@/components/forecast";
import { GovernancePanel, MergeCounts } from "@/components/governance";
import { PathToGreen } from "@/components/path-to-green";
import { ReachabilityCard } from "@/components/reachability";
import { RiskProfileCard } from "@/components/risk-profile";
import { ScanHealthBoxes } from "@/components/scan-health";
import { ReleaseEvidence, SscsTab } from "@/components/sscs";
import { VulnerablePackages } from "@/components/vulnerable-packages";
import { Surfaces } from "@/components/surfaces";
import { SsdfTab } from "@/components/ssdf";
import { ThreatModelTab } from "@/components/threat-model";
import {
  ALL_CAPABILITIES,
  Crumb,
  EmptyState,
  ErrorPanel,
  Label,
  Pill,
  Section,
} from "@/components/primitives";
import type { CiPage, ScanHealth, WorkflowsPage } from "@/lib/api";
import {
  getCi,
  getDecisions,
  getFinding,
  getInsiderRisk,
  getOpenFindings,
  getRemediation,
  getRepoGuidance,
  getRepo,
  getReachability,
  getRiskProfile,
  getRiskProfileProposal,
  getGovernance,
  getSsdf,
  getScanHealth,
  getScanRunTrend,
  getSscs,
  getSurfaces,
  getVulnerablePackages,
  getThreatModel,
  getWorkflows,
} from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * Ten tabs, in this order (spec 18 §2).
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
  // Directly after Findings, because it is the same backlog asked the next
  // question. Findings says what is outstanding here; this says which of it is
  // work today — and it is the estate page's reasoning applied to one
  // repository rather than a second, quietly different, ranking.
  { id: "remediate", label: "Remediate today" },
  { id: "harness", label: "Harness" },
  { id: "threat-model", label: "Threat Model" },
  { id: "sscs", label: "Supply chain" },
  { id: "insider", label: "Insider Threat" },
  { id: "decisions", label: "Risk Decision" },
  { id: "remediation", label: "Remediation" },
  // Last, because it is the only tab nobody opens to do work: it answers
  // "what can we show an assessor" rather than "what should I fix". Its own
  // tab rather than a panel under Insider Threat — that tab is about who
  // merged what, and adherence is a different question with a different
  // reader.
  { id: "adherence", label: "Adherence" },
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

  // An unknown id used to fall through the ternary below and render Dashboard,
  // so a wrong link looked like a working one. The incident page shipped with
  // `?tab=supply-chain` — not a tab id; the id is `sscs` — and nothing said so
  // for as long as it was wrong.
  if (!TABS.some((entry) => entry.id === tab)) {
    return (
      <ErrorPanel
        title="No such tab"
        detail={`'${tab}' is not a tab on this page. Valid ids: ${TABS.map(
          (entry) => entry.id,
        ).join(", ")}.`}
      />
    );
  }

  const repo = await getRepo(repoId);
  if (!repo.ok) {
    return <ErrorPanel title="Repository unavailable" detail={repo.error} />;
  }

  // Fetched once per page load regardless of which tab is open: the
  // Built/Scanned-by links (spec 17 §2.3) render at the top of every tab, the
  // Harness tab's capability buttons (spec 17 §2.2) need the same `CiPage` to
  // colour themselves consistently with the panel below them, and Dashboard
  // (spec 18 §3) reuses both rather than issuing its own copies.
  // `getWorkflows` joins them because the Dashboard tab's switches (spec 32
  // §6) need GitHub's live view of each workflow's state, which is derived on
  // every read rather than stored. One GitHub call per repository page — the
  // fan-out §7.1 warns about is the *portfolio*, which does not read this.
  const [scanHealth, ci, workflows] = await Promise.all([
    getScanHealth(repoId),
    getCi(repoId),
    getWorkflows(repoId),
  ]);
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
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[13px] text-critical">
          {ci.error}
        </p>
      )}

      {repo.data.pending_capabilities?.length ? (
        <div className="border border-high bg-high-wash px-3 py-2 text-[13px] text-ink-2">
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
            className={`-mb-0.5 border-b-2 px-3 py-1.5 font-mono text-[12px] ${
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
      ) : tab === "remediate" ? (
        <RemediateToday repoId={repoId} />
      ) : tab === "adherence" ? (
        <AdherenceTab repoId={repoId} />
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
          workflows={workflows.ok ? workflows.data : null}
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
  workflows,
}: {
  repoId: string;
  enabled: string[];
  pending: string[];
  live: string[];
  scanHealth: ScanHealth | null;
  scanHealthError: string | null;
  ci: CiPage | null;
  /** Null when the read failed. The panel is then omitted rather than
   *  rendered empty — "no workflows" and "could not ask GitHub" are
   *  different facts, and the backend already distinguishes them through
   *  `unavailable` when it can answer at all. */
  workflows: WorkflowsPage | null;
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

      {/* Scan health and Enabled jobs were two panels asking the same
          question from different ends — how is each check doing — and reading
          them meant joining two grids by eye.
          
          One section, two blocks, one header and one legend. Not one *grid*:
          a job carries a name and no capability, so merging the tiles would
          mean duplicating the backend's job-to-capability map in the browser,
          where it would drift silently the first time a template renamed a
          job. Sitting them together is the honest consolidation; pretending
          the data supports a row-level join is not. */}
      <Section
        title="Checks"
        detail="how each one is running, and which jobs back it"
        aside={
          scanHealth ? (
            <span className="font-mono text-[12px] text-ink-3">
              {reported.length} of {boxes.length} have ever run
              {ci?.pipeline ? ` · ${ci.pipeline}` : ""}
            </span>
          ) : null
        }
      >
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1">
            <div className="px-3 pt-1">
              <Label>Run health</Label>
            </div>
            {scanHealthError ? (
              <p className="px-3 py-2 text-[13px] text-critical">{scanHealthError}</p>
            ) : (
              <ScanHealthBoxes capabilities={boxes} health={scanHealth?.capabilities ?? []} />
            )}
          </div>

          <div className="flex flex-col gap-1 border-t border-rule pt-2">
            <div className="px-3">
              <Label>Jobs</Label>
            </div>
            {ci ? (
              <>
                <JobLights ci={ci} />
                <ReportingGaps reporting={ci.reporting ?? []} />
              </>
            ) : (
              // Said rather than dropped. A block that quietly disappears when
              // its fetch fails reads as a repository with no pipeline.
              <p className="px-3 py-2 text-[13px] text-critical">
                Pipeline state could not be read.
              </p>
            )}
          </div>
        </div>
      </Section>

      {workflows ? <WorkflowSwitches repoId={repoId} page={workflows} /> : null}
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

/** The security scans this tab can also start, in the order somebody reaches
 *  for them: the code, then the running application, then what it is built
 *  from. Every one is in `DISPATCHABLE_CAPABILITIES` on the backend, so none
 *  of these buttons can be offered for something the dispatch endpoint would
 *  refuse.
 *
 *  Kept apart from the tests above, and labelled apart, because the two differ
 *  in the way that matters: a test produces a run and a count (D-046), while a
 *  scan produces findings that enter Oracle's risk score and stay open until
 *  two consecutive successful scans see them gone. Starting one is a heavier
 *  act than re-running a test suite and the tab should not imply otherwise. */
const SECURITY_CAPABILITIES = [
  { id: "sast", label: "SAST", detail: "static analysis of the source" },
  { id: "dast", label: "DAST", detail: "against the running application" },
  { id: "secrets", label: "Secrets", detail: "credentials in git history" },
  { id: "containers", label: "Containers", detail: "OS packages in the image" },
  { id: "iac", label: "IaC", detail: "infrastructure definitions" },
  { id: "atlas", label: "Dependencies", detail: "advisories against the tree" },
] as const;

/**
 * Start a security scan from the Harness tab.
 *
 * **Only what is enabled.** A repository without a DAST lane gets no DAST
 * button rather than a button that returns "not enabled" — the same rule the
 * remediation surfaces follow, and for the same reason: an affordance that
 * looks like capability and is not is worse than an absence (B-021).
 *
 * Each capability dispatches on its own. Re-running every lane because one is
 * stale is wasteful on a runner and noisy in the record, and the endpoint has
 * taken a capability scope since spec 17 §2.5 — it simply was not offered
 * anywhere a person could reach it.
 */
function SecurityScans({
  repoId,
  enabled,
  reported,
}: {
  repoId: string;
  enabled: string[];
  reported: string[];
}) {
  const available = SECURITY_CAPABILITIES.filter(
    (capability) =>
      enabled.includes(capability.id) || reported.includes(capability.id),
  );

  return (
    <section className="flex flex-col gap-2 border-t border-rule pt-3">
      <Label>Security scans</Label>
      <p className="max-w-prose text-[14px] leading-relaxed text-ink-2">
        <strong className="text-ink">These produce findings, not a score.</strong>{" "}
        A scan started here writes findings that enter this repository&rsquo;s risk
        decision and stay open until two consecutive successful scans see them
        gone. That is a heavier act than re-running a test suite, which is why
        they sit apart from the lanes above.
      </p>

      {available.length === 0 ? (
        <EmptyState
          title="No scanning capability is enabled"
          detail="Enable one on the Dashboard tab. Only enabled capabilities are offered here, so a button always corresponds to a lane that exists."
        />
      ) : (
        <div className="flex flex-col gap-1.5">
          {available.map((capability) => (
            <div
              key={capability.id}
              className="flex flex-wrap items-center justify-between gap-2 border-b border-rule-soft pb-1.5 last:border-0"
            >
              <span className="font-mono text-[12px] text-ink-2">
                <strong className="text-ink">{capability.label}</strong>
                <span className="ml-2 text-ink-3">{capability.detail}</span>
              </span>
              <ScanNowButton
                repoId={repoId}
                capabilities={[capability.id]}
                label={`run ${capability.id}`}
              />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

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
      <p className="max-w-prose border-l-2 border-rule bg-paper-2 px-3 py-2 text-[14px] leading-relaxed text-ink-2">
        <strong className="text-ink">Pass/fail, not findings.</strong> Unit,
        functional, and QA-doc checks record a run and a count, never a
        security finding — a failing test cannot lower this repository&rsquo;s
        risk score by being suppressed the way a finding can. An
        Actions-scanned repository enables these the same way as any other
        capability, and each lane needs a{" "}
        <span className="font-mono">command</span> in its config — this
        platform does not guess a repository&rsquo;s test runner.
      </p>

      <div className="flex flex-wrap items-start justify-between gap-3">
        <span className="font-mono text-[12px] text-ink-3">
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

      <SecurityScans repoId={repoId} enabled={enabled} reported={reported} />

      <Section title="Test health" detail="pass/fail, most recent run">
        {scanHealth.ok ? (
          boxes.length > 0 ? (
            <ScanHealthBoxes capabilities={boxes} health={scanHealth.data.capabilities} />
          ) : (
            <p className="px-3 py-3 text-[13px] text-ink-3">
              Nothing to show until unit, functional, or qa is enabled.
            </p>
          )
        ) : (
          <p className="px-3 py-2 text-[13px] text-critical">{scanHealth.error}</p>
        )}
      </Section>

      {boxes.map((capability) => (
        <LaneTrend
          key={capability}
          repoId={repoId}
          capability={capability}
          health={
            scanHealth.ok
              ? scanHealth.data.capabilities.find((c) => c.capability === capability)
              : undefined
          }
        />
      ))}
    </div>
  );
}

/** One lane's pass rate over time (spec 19 §1.1) — its own component so each
 *  lane's fetch is independent: a trend that fails to load for `qa` should
 *  not take `unit`'s down with it. */
async function LaneTrend({
  repoId,
  capability,
  health,
}: {
  repoId: string;
  capability: string;
  health: ScanHealth["capabilities"][number] | undefined;
}) {
  const trend = await getScanRunTrend(repoId, capability);
  return (
    <Section title={`${capability} — pass rate`} detail="last 90 days">
      <div className="px-3 py-2">
        {trend.ok ? (
          <PassRateSparkline capability={capability} points={trend.data.points} />
        ) : (
          <p className="text-[13px] text-critical">{trend.error}</p>
        )}
      </div>
      {/* Beside the sparkline rather than in a section of its own (spec 31
          §4): the whole value of this number is that it qualifies the one
          above it, and a reader who has to go looking for the qualification
          will not. */}
      <div className="border-t border-rule-soft px-3 py-2">
        <TestCoverage row={health} />
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
  // Guidance alongside the findings. The detail pane said what was wrong and
  // never what to do about it, while the scanners had been carrying the answer
  // in every report all along (B-032).
  const [findings, guidance] = await Promise.all([
    getOpenFindings(repoId, {
      severity: query.severity,
      capability: query.capability,
      finding_status: query.status,
      rule_id: query.rule_id,
      kev_only: query.kev_only === "1",
      min_epss: query.min_epss ? Number(query.min_epss) : undefined,
      triage: query.triage,
      fixable: query.fixable === "1" ? true : undefined,
    }),
    getRepoGuidance(repoId),
  ]);

  if (!findings.ok) {
    return <ErrorPanel title="Findings unavailable" detail={findings.error} />;
  }

  // Flattened to rule -> remediation once here rather than searched per row.
  // A failed guidance fetch costs the "what to do" block and nothing else:
  // the findings were the tab before this and must still be.
  const fixByRule: Record<string, { fix: string; source: string; effort: string }> = {};
  if (guidance.ok) {
    for (const capability of guidance.data.by_rule) {
      for (const rule of capability.rules) {
        fixByRule[rule.rule_id] = {
          fix: rule.fix,
          source: rule.source,
          effort: rule.effort,
        };
      }
    }
  }

  return (
    <OpenFindings
      repoId={repoId}
      page={findings.data}
      query={query}
      fixByRule={fixByRule}
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
      <p className="border-t border-rule pt-2 text-[12px] text-critical">
        {result.error}
      </p>
    );
  }
  return (
    <div className="flex flex-col gap-2">
      {result.data.code_snippet ? (
        <pre className="scroll-x max-h-40 border border-rule bg-paper p-2 font-mono text-[12px] leading-relaxed">
          {result.data.code_snippet}
        </pre>
      ) : null}
      {result.data.fingerprint_version === "v1-line" ? (
        <p className="border-l-2 border-high bg-high-wash px-2 py-1 text-[12px] text-ink-2">
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
  const [result, profile, proposal, reachability] = await Promise.all([
    getDecisions(repoId),
    getRiskProfile(repoId),
    getRiskProfileProposal(repoId),
    getReachability(repoId),
  ]);
  if (!result.ok) {
    return <ErrorPanel title="Decisions unavailable" detail={result.error} />;
  }
  // The newest decision carries the inverse of its own score (spec 26 §1).
  // Read from the decision rather than fetched separately: a path computed by
  // a second call could disagree with the score it is supposed to explain.
  const latest = result.data.decisions[0];
  const snapshot = latest?.inputs_snapshot as
    | {
        path_to_green?: Parameters<typeof PathToGreen>[0]["path"];
        forecast?: Parameters<typeof AgeForecast>[0]["forecast"];
      }
    | undefined;
  const path = snapshot?.path_to_green ?? null;

  return (
    <div className="flex flex-col gap-4">
      {/* Above the path, because it is the one thing here about a score that
          has not happened yet (spec 26 §4). Renders nothing when ageing alone
          does not cross a band, which is most of the time. */}
      <AgeForecast forecast={snapshot?.forecast ?? null} />
      <PathToGreen repoId={repoId} path={path} />
      {profile.ok ? (
        <RiskProfileCard
          repoId={repoId}
          profile={profile.data}
          proposal={proposal.ok ? proposal.data : null}
        />
      ) : (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[13px] text-critical">
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
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[13px] text-critical">
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
  // Concurrently: the trust score and the package list are two reads of
  // different things, and in series the tab waits for the slower one twice.
  const [result, packages] = await Promise.all([
    getSscs(repoId),
    getVulnerablePackages(repoId),
  ]);
  if (!result.ok) {
    return <ErrorPanel title="Supply-chain evidence unavailable" detail={result.error} />;
  }
  return (
    <div className="flex flex-col gap-5">
      <SscsTab evidence={result.data.evidence} latest={result.data.latest ?? null} />
      {/* The scores above say how trustworthy the tree is; this says which
          packages are the reason and what can be done about each (B-027). A
          failure here loses the table, not the whole tab. */}
      {packages.ok ? (
        <VulnerablePackages data={packages.data} />
      ) : (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[12px] text-critical">
          {packages.error}
        </p>
      )}
      {/* Last, and collapsed. It is a record rather than a question — read
          when somebody needs the SBOM for a specific release — and it was
          sitting above what people come to this tab for (B-031). */}
      <ReleaseEvidence repoId={repoId} evidence={result.data.evidence} />
    </div>
  );
}

async function ThreatModelTabPanel({ repoId }: { repoId: string }) {
  // Concurrently, and the register is allowed to fail on its own: the STRIDE
  // view was the whole tab before this and must not go down with an addition
  // to it.
  const [result, surfaces] = await Promise.all([
    getThreatModel(repoId),
    getSurfaces(repoId),
  ]);
  if (!result.ok) {
    return <ErrorPanel title="Threat model unavailable" detail={result.error} />;
  }
  return (
    <div className="flex flex-col gap-5">
      {/* What this repository *is*, above what was found in it. A threat model
          is assets, entry points, trust boundaries and mitigations; the tab
          had the last one and the findings, and read as an inventory of
          problems with nothing at stake (B-029). */}
      {surfaces.ok ? (
        <Surfaces repoId={repoId} data={surfaces.data} />
      ) : (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[12px] text-critical">
          {surfaces.error}
        </p>
      )}
      <ThreatModelTab repoId={repoId} page={result.data} />
    </div>
  );
}

async function AegisTab({ repoId }: { repoId: string }) {
  // Fetched alongside rather than nested: a governance read that fails — an
  // App without `administration: read` is the common case — must not take the
  // signals down with it, and the signals were the whole tab until now.
  const [result, posture] = await Promise.all([
    getInsiderRisk(repoId),
    getGovernance(repoId),
  ]);
  if (!result.ok) {
    return <ErrorPanel title="Insider risk unavailable" detail={result.error} />;
  }
  return (
    <div className="flex flex-col gap-4">
      {/* Above the signals, because it explains them (spec 30 §2). Every
          signal below describes a pull request after the fact;
          `self_approval` firing is a symptom, and "self-approval is permitted
          on the default branch" is the cause. */}
      {posture.ok ? (
        <>
          <GovernancePanel posture={posture.data} />
          <MergeCounts merges={posture.data.merges} />
        </>
      ) : (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[13px] text-ink-3">
          {posture.error}
        </p>
      )}

      <InsiderRiskTab
        repoFullName={result.data.repo_full_name}
        signals={result.data.signals}
        detailIncluded={result.data.detail_included}
        governance={result.data.governance}
        blocking={result.data.blocking}
      />
    </div>
  );
}

async function AdherenceTab({ repoId }: { repoId: string }) {
  const result = await getSsdf(repoId);
  if (!result.ok) {
    return <ErrorPanel title="Adherence unavailable" detail={result.error} />;
  }
  return <SsdfTab data={result.data} />;
}

async function PatchworkTab({ repoId }: { repoId: string }) {
  const [result, guidance] = await Promise.all([
    getRemediation(repoId),
    getRepoGuidance(repoId),
  ]);
  if (!result.ok) {
    return <ErrorPanel title="Remediation unavailable" detail={result.error} />;
  }
  return (
    <div className="flex flex-col gap-5">
      {/* What the reports recommend, above what Patchwork managed. The tab was
          only ever the second of those, and across this estate the second is
          almost always "nothing" — four fixers covering four narrow classes,
          reporting zero beside reports full of advice nobody read (B-030). */}
      {guidance.ok ? (
        <RecommendedFixes data={guidance.data} />
      ) : (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[12px] text-critical">
          {guidance.error}
        </p>
      )}
      <div className="border-t border-rule pt-4">
        <RemediationTab
          events={result.data.events}
          openDraftPrs={result.data.open_draft_prs}
          note={result.data.note}
        />
      </div>
    </div>
  );
}
