/**
 * The Risk page's reads (TheHub #61139, review of #1080): the gate asks for
 * the newest commit_gate only, so a busy history of other decision types
 * cannot push it out of the page and read "not assessed"; and the
 * open-findings reads keep their counts, so a capped read can say "at least".
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

const GET = vi.fn();
vi.mock("@/lib/api", () => ({
  BackendUnavailable: class extends Error {},
  backendClient: () => ({ GET }),
}));

import { getRiskInputs } from "@/lib/server-risk";

const ok = new Response(null, { status: 200 });
let openFindings = { groups: [], matching: 0, shown: 0, truncated: false };

beforeEach(() => {
  openFindings = { groups: [], matching: 0, shown: 0, truncated: false };
  GET.mockReset();
  GET.mockImplementation(async (path: string) => {
    switch (path) {
      case "/api/dashboard/portfolio":
        return {
          response: ok,
          data: {
            repos: [
              {
                repo_id: "r1",
                repo_full_name: "o/beacon",
                status: "active",
                synthetic: false,
                severity_counts: {},
                enabled_capabilities: [],
                capability_states: [],
                last_scan_at: null,
              },
            ],
          },
        };
      case "/api/oracle/decisions/{repo_id}":
        return {
          response: ok,
          data: { decisions: [{ decision_type: "commit_gate", commit_sha: "a".repeat(40) }] },
        };
      case "/api/oracle/decisions/by-commit/{commit_sha}":
        return { response: ok, data: { found: true, commit_sha: "a".repeat(40), recommendation: "go" } };
      case "/api/dashboard/repos/{repo_id}/open-findings":
        return { response: ok, data: openFindings };
      case "/api/dashboard/repos/{repo_id}/risk-acceptances":
        return { response: ok, data: { acceptances: [] } };
      case "/api/dashboard/deployments":
        return { response: ok, data: { repos: [] } };
      case "/api/approvals":
        return { response: ok, data: [] };
      default:
        return { response: new Response(null, { status: 404 }), data: undefined };
    }
  });
});

describe("the gate read", () => {
  it("asks for the newest commit_gate only: decision_type=commit_gate, limit=1", async () => {
    const result = await getRiskInputs({ benchmark: false });
    expect(result.ok).toBe(true);
    const call = GET.mock.calls.find(([path]) => path === "/api/oracle/decisions/{repo_id}");
    expect(call).toBeDefined();
    expect(call![1].params.query).toEqual({ decision_type: "commit_gate", limit: 1 });
  });
});

describe("the open-findings reads", () => {
  it("keep matching, shown and truncated", async () => {
    openFindings = { groups: [], matching: 2500, shown: 2000, truncated: true };
    const result = await getRiskInputs({ benchmark: false });
    if (!result.ok) throw new Error(result.error);
    for (const read of [result.data.reads.r1.overdue, result.data.reads.r1.highPlus]) {
      expect(read).toEqual({ ok: true, data: { groups: [], matching: 2500, shown: 2000, truncated: true } });
    }
  });
});
