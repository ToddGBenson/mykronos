/**
 * The Risk page's reads (TheHub #61139), from existing endpoints only.
 *
 * - `/api/dashboard/portfolio`: the products, severity counts and lanes.
 * - `/api/dashboard/deployments`: production's lag behind its branch.
 * - `/api/approvals?state=pending`: what waits on a person.
 * - Per product, in parallel:
 *   - `/api/oracle/decisions/{repo_id}?decision_type=commit_gate&limit=1`
 *     for the newest `commit_gate` decision's sha (asked for by type, so
 *     other decision types cannot push it out of the page), then `/api/oracle/decisions/by-commit/{sha}` for the
 *     verdict that stands on it, overrides and introduced blocking findings
 *     included (the question `deploy.ps1` asks);
 *   - `/open-findings` twice: open critical and high (oldest, and the age
 *     chart), and open past their target (overdue). Each reads up to 2000
 *     occurrences, and keeps `matching`, `shown` and `truncated`, so a read
 *     cut short draws its counts as floors ("at least");
 *   - `/risk-acceptances`: acceptances in force and expiring.
 *
 * A failed per-product read is kept as a failure, so the page draws that
 * cell as unknown rather than as zero.
 */

import "server-only";

import { BackendUnavailable, backendClient, type PortfolioRow } from "./api";
import type { DeployLag } from "./prod-lag";
import type {
  ApprovalLite,
  CommitGate,
  FindingsRead,
  Read,
  RiskAcceptanceLite,
  RiskGroup,
  RiskInputs,
  RiskRepoReads,
} from "./risk-page";

function failed(error: unknown): { ok: false; error: string } {
  if (error instanceof BackendUnavailable) return { ok: false, error: error.detail };
  const message = error instanceof Error ? error.message : String(error);
  if (/fetch failed|ECONNREFUSED|ENOTFOUND/i.test(message)) {
    return { ok: false, error: "Cannot reach the Mykronos API." };
  }
  return { ok: false, error: message };
}

function status(response: Response | undefined, what: string): string {
  if (!response) return `Could not load ${what}`;
  if (response.status === 401 || response.status === 503) {
    return "The API rejected this request. Set MYKRONOS_ADMIN_TOKEN on the frontend.";
  }
  return `Could not load ${what} (HTTP ${response.status})`;
}

async function read<T>(what: string, call: () => Promise<{ data?: unknown; response: Response }>, pick: (data: never) => T): Promise<Read<T>> {
  try {
    const { data, response } = await call();
    if (data === undefined || data === null) return { ok: false, error: status(response, what) };
    return { ok: true, data: pick(data as never) };
  } catch (error) {
    return failed(error);
  }
}

type Client = ReturnType<typeof backendClient>;

const OPEN_FINDINGS = "/api/dashboard/repos/{repo_id}/open-findings" as const;

function findingsOf(page: {
  groups: RiskGroup[];
  matching: number;
  shown: number;
  truncated: boolean;
}): FindingsRead {
  return {
    groups: page.groups.map((g) => ({
      severity: g.severity,
      occurrences: g.occurrences,
      age_days: g.age_days ?? null,
      first_seen_at: g.first_seen_at ?? null,
      due_at: g.due_at ?? null,
      due_state: g.due_state,
    })),
    matching: page.matching,
    shown: page.shown,
    truncated: page.truncated,
  };
}

async function gateRead(client: Client, repoId: string): Promise<Read<CommitGate | null>> {
  const history = await read(
    "decisions",
    () =>
      client.GET("/api/oracle/decisions/{repo_id}", {
        params: { path: { repo_id: repoId }, query: { decision_type: "commit_gate", limit: 1 } },
        cache: "no-store",
      }),
    (data: { decisions?: { decision_type?: string; commit_sha?: string | null }[] }) =>
      (data.decisions ?? []).find((d) => d.decision_type === "commit_gate" && d.commit_sha)?.commit_sha ?? null,
  );
  if (!history.ok) return history;
  const sha = history.data;
  if (!sha) return { ok: true, data: null };
  return read(
    "the commit gate",
    () =>
      client.GET("/api/oracle/decisions/by-commit/{commit_sha}", {
        params: { path: { commit_sha: sha } },
        cache: "no-store",
      }),
    (data: CommitGate) => data,
  );
}

async function repoReads(client: Client, repoId: string): Promise<RiskRepoReads> {
  const [gate, highPlus, overdue, acceptances] = await Promise.all([
    gateRead(client, repoId),
    read(
      "open high and critical findings",
      () =>
        client.GET(OPEN_FINDINGS, {
          params: {
            path: { repo_id: repoId },
            query: { finding_status: ["open"], severity: ["critical", "high"], limit: 2000 } as never,
          },
          cache: "no-store",
        }),
      findingsOf,
    ),
    read(
      "overdue findings",
      () =>
        client.GET(OPEN_FINDINGS, {
          params: {
            path: { repo_id: repoId },
            query: { finding_status: ["open"], due: ["overdue"], limit: 2000 } as never,
          },
          cache: "no-store",
        }),
      findingsOf,
    ),
    read(
      "risk acceptances",
      () =>
        client.GET("/api/dashboard/repos/{repo_id}/risk-acceptances", {
          params: { path: { repo_id: repoId }, query: {} },
          cache: "no-store",
        }),
      (data: { acceptances: RiskAcceptanceLite[] }): RiskAcceptanceLite[] =>
        data.acceptances.map((a) => ({ id: a.id, state: a.state, days_left: a.days_left })),
    ),
  ]);
  return { gate, highPlus, overdue, acceptances };
}

/**
 * Everything the page needs, or why the product list itself could not be
 * read. Benchmark repositories are read only when they will be shown.
 */
export async function getRiskInputs(options: {
  benchmark: boolean;
}): Promise<{ ok: true; data: RiskInputs; asOf: number } | { ok: false; error: string }> {
  const client = backendClient();
  const portfolio = await read(
    "the portfolio",
    () =>
      client.GET("/api/dashboard/portfolio", {
        params: { query: { include_removed: false } },
        cache: "no-store",
      }),
    (data: { repos: PortfolioRow[] }) => data.repos,
  );
  if (!portfolio.ok) return portfolio;

  const shown = portfolio.data.filter(
    (r) => r.status === "active" && (options.benchmark || !r.synthetic),
  );

  const [deployments, approvals, perRepo] = await Promise.all([
    read(
      "deployments",
      () => client.GET("/api/dashboard/deployments", { cache: "no-store" }),
      (data: { repos: { repo_full_name: string; lag?: DeployLag | null }[] }) =>
        Object.fromEntries(data.repos.map((r) => [r.repo_full_name, r.lag ?? null])),
    ),
    read(
      "approval requests",
      () => client.GET("/api/approvals", { params: { query: { state: "pending" } }, cache: "no-store" }),
      (data: ApprovalLite[]): ApprovalLite[] =>
        data.map((a) => ({ id: a.id, duty: a.duty, subject_ref: a.subject_ref, expires_at: a.expires_at })),
    ),
    Promise.all(shown.map(async (r) => [r.repo_id, await repoReads(client, r.repo_id)] as const)),
  ]);

  return {
    ok: true,
    // When the reads finished: the clock the page measures "last 24 hours"
    // and lapsed requests against, and the time it says it is as of.
    asOf: Date.now(),
    data: {
      repos: portfolio.data.map((r) => ({
        repo_id: r.repo_id,
        repo_full_name: r.repo_full_name,
        status: r.status,
        synthetic: r.synthetic,
        severity_counts: r.severity_counts,
        enabled_capabilities: r.enabled_capabilities,
        capability_states: r.capability_states,
        last_scan_at: r.last_scan_at,
      })),
      deployments,
      approvals,
      reads: Object.fromEntries(perRepo),
    },
  };
}
