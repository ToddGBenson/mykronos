/**
 * Typed access to the Mykronos backend.
 *
 * The admin token never reaches the browser. Every call from a client
 * component goes to a Next route handler on this server, which attaches the
 * token from a server-only environment variable and forwards the request.
 *
 * That matters more than it looks. The Phase 1 auth stub is a single bearer
 * token with full admin rights (spec 12 §3 replaces it with SSO). Shipping
 * that token to the browser would put a credential that can offboard repos
 * into localStorage, one XSS away from anyone. Proxying keeps it server-side
 * and costs one hop.
 */

import createClient from "openapi-fetch";
import type { paths } from "./api-types";

/** Server-side only. Never import this from a client component. */
export function backendClient() {
  const baseUrl = process.env.MYKRONOS_API_URL ?? "http://127.0.0.1:8000";
  const token = process.env.MYKRONOS_ADMIN_TOKEN ?? "";

  return createClient<paths>({
    baseUrl,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

export type Portfolio =
  paths["/api/dashboard/portfolio"]["get"]["responses"]["200"]["content"]["application/json"];
export type PortfolioRow = Portfolio["repos"][number];
export type PortfolioSummary = Portfolio["summary"];
export type FindingsPage =
  paths["/api/dashboard/repos/{repo_id}/findings"]["get"]["responses"]["200"]["content"]["application/json"];
export type RepoList =
  paths["/api/repos"]["get"]["responses"]["200"]["content"]["application/json"];
export type RepoDetail =
  paths["/api/repos/{repo_id}"]["get"]["responses"]["200"]["content"]["application/json"];

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/**
 * A finding row as the dashboard returns it.
 *
 * Loosely typed on purpose: the API omits `code_snippet` and
 * `raw_finding_json` entirely for viewer roles (spec 12 §5), so the shape
 * genuinely differs by caller and pretending otherwise would mean lying to
 * the type checker about fields that may not be there.
 */
export type Finding = {
  finding_id: string;
  capability: string;
  rule_id: string;
  title: string;
  description?: string | null;
  severity: Severity;
  cvss_score?: number | null;
  file_path?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  symbol?: string | null;
  package_name?: string | null;
  package_version?: string | null;
  status: string;
  fingerprint_version?: string | null;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  resolved_at?: string | null;
  code_snippet?: string | null;
  raw_finding_json?: unknown;
};

export type ScanHealth = {
  repo_full_name: string;
  capabilities: {
    capability: string;
    runs: number;
    succeeded: number;
    failed: number;
    no_applicable_targets: number;
    failure_rate: number;
    last_run_at: string | null;
    peak_findings: number;
  }[];
};

/** Backend unreachable is a normal state here, not an exception. */
export class BackendUnavailable extends Error {
  constructor(readonly detail: string) {
    super(detail);
    this.name = "BackendUnavailable";
  }
}
