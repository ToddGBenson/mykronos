/**
 * What THIS change did, headlined beside the standing posture (TheHub #60914).
 *
 * A TheHub commit that passed every lane and introduced nothing read
 * "no_go 100/100" on its delivery row, so every row read the same and the
 * gate taught developers to ignore it. Each row now leads with the change
 * verdict, and shows the Oracle recommendation and score apart from it,
 * labelled as posture.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { DeliveryView } from "@/components/po-console";
import { RiskMatrix } from "@/components/risk-page";
import type { PoDelivery } from "@/lib/po-console";
import { buildRiskPage, type RiskInputs } from "@/lib/risk-page";

type Change = {
  verdict: "clean" | "introduces_blocking" | "unknown";
  blocking: number | null;
  non_blocking: number | null;
  overridden: boolean;
  text: string;
};

function row(sha: string, change: Change) {
  return {
    sha,
    commit_url: `https://github.com/o/beacon/commit/${sha}`,
    shipped: true,
    shipped_reason: "scanned on main",
    branches: ["main"],
    pr_numbers: [],
    first_seen: "2026-11-01T10:00:00",
    last_seen: "2026-11-01T10:00:00",
    scans: [],
    scan_failures: 0,
    decision: {
      decision_type: "commit_gate",
      recommendation: "no_go",
      score: 100,
      evaluated_at: "2026-11-01T10:00:00",
      gate_outcome: null,
      human_override: null,
      change,
      posture: { recommendation: "no_go", score: 100, text: "posture: no_go 100/100" },
    },
    deployed: "not_recorded",
  };
}

function delivery(rows: ReturnType<typeof row>[]): PoDelivery {
  return {
    repo_full_name: "o/beacon",
    default_branch: "main",
    days: 30,
    deployment: {
      running_revision: null,
      probe_status: "not_configured",
      probe_source: null,
      observed_at: null,
      lag: null,
      missing: [],
    },
    shipped: rows,
    not_shipped: [],
    error: null,
    commits_error: null,
  } as unknown as PoDelivery;
}

const CLEAN: Change = {
  verdict: "clean",
  blocking: 0,
  non_blocking: 0,
  overridden: false,
  text: "change: clean",
};

describe("a delivery row leads with the change (TheHub #60914)", () => {
  it("a clean commit on a no_go backlog reads clean first, and the posture after it, labelled", () => {
    const html = renderToStaticMarkup(
      createElement(DeliveryView, { repoId: "r1", data: delivery([row("5".repeat(40), CLEAN)]) }),
    );
    const change = html.indexOf("change: clean");
    const posture = html.indexOf("posture: no_go 100/100");
    expect(change).toBeGreaterThan(-1);
    expect(posture).toBeGreaterThan(change);
    // The recommendation is no longer the row's headline pill.
    expect(html).not.toMatch(/>no_go</);
  });

  it("a commit that introduced blocking findings says how many", () => {
    const html = renderToStaticMarkup(
      createElement(DeliveryView, {
        repoId: "r1",
        data: delivery([
          row("b".repeat(40), {
            verdict: "introduces_blocking",
            blocking: 2,
            non_blocking: 0,
            overridden: false,
            text: "change: introduces 2 blocking",
          }),
        ]),
      }),
    );
    expect(html).toContain("change: introduces 2 blocking");
    expect(html).toContain('data-change="introduces_blocking"');
  });

  it("an unread count says unknown, never clean", () => {
    const html = renderToStaticMarkup(
      createElement(DeliveryView, {
        repoId: "r1",
        data: delivery([
          row("c".repeat(40), {
            verdict: "unknown",
            blocking: null,
            non_blocking: null,
            overridden: false,
            text: "change: unknown (what this commit introduced could not be read)",
          }),
        ]),
      }),
    );
    expect(html).toContain('data-change="unknown"');
    expect(html).not.toContain("change: clean");
  });
});

describe("the Risk page draws the posture beside the gate's change verdict", () => {
  it("renders the posture as its own text next to the pill", () => {
    const inputs: RiskInputs = {
      repos: [
        {
          repo_id: "r1",
          repo_full_name: "o/beacon",
          status: "active",
          synthetic: false,
          severity_counts: { critical: 0, high: 0, medium: 0 },
          enabled_capabilities: [],
          capability_states: [],
          last_scan_at: null,
        },
      ],
      reads: {
        r1: {
          gate: ok({
            found: true,
            commit_sha: "5".repeat(40),
            effective_recommendation: "no_go",
            overall_risk_score: 100,
            introduced: {},
            introduced_blocking: false,
          }),
          highPlus: ok([]),
          overdue: ok([]),
          acceptances: ok([]),
        },
      },
      deployments: ok({}),
      approvals: ok([]),
    };
    const html = renderToStaticMarkup(
      createElement(RiskMatrix, { page: buildRiskPage(inputs, { now: Date.parse("2026-11-01T12:00:00Z") }) }),
    );
    expect(html).toContain(">clean<");
    expect(html).toContain("posture no_go 100/100");
  });
});

function ok<T>(data: T) {
  return { ok: true as const, data };
}
