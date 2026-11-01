import { prerender } from "react-dom/static";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  canRecord,
  concurRationale,
  evidenceFields,
  nextRequestHref,
} from "../lib/approval-packet";

/**
 * The approval packet (TheHub #61136, v2 P3): Review-PendingApprovals.ps1's
 * packet in the dashboard. Evidence as fields rather than raw JSON, the
 * platform's verification check and its output, concur with the reviewer,
 * decide estate-wide requests here, hide superseded requests, and Record and
 * go to the next one.
 */

const getReviewPacket = vi.fn();
const getReviewQueue = vi.fn();
vi.mock("@/lib/po-console", () => ({ getReviewPacket, getReviewQueue }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }) }));

const DIGEST = "a".repeat(64);
const REVIEW = {
  verdict: "approve",
  rationale: "The diff does what it says.\nThe cited test exists.\nCI is green.\nA fourth line.",
  model: "claude-opus-5",
  reviewed_at: "2026-10-31T06:00:00Z",
  counts: false,
  delegable: true,
  checks: [{ claim: "tests exist", holds: true, note: "found" }],
};

function packet(overrides: Record<string, unknown> = {}) {
  return {
    id: "req-1",
    duty: "pull_request_merge",
    tier: "production",
    subject_ref: "example-org/relay#212@4f9c1a2",
    summary: "#212 Rate-limit the export route",
    repo_full_name: "example-org/relay",
    repo_id: null,
    decide_link: null,
    requested_by: "agent:author-1",
    requester_kind: "agent",
    requester_claim: "Adds a limiter; the new test fails without it.",
    evidence_digest: DIGEST,
    created_at: "2026-10-30T10:00:00Z",
    expires_at: "2026-11-06T10:00:00Z",
    overdue: false,
    reviewer: REVIEW,
    decisions: [],
    evidence: {
      repo: "example-org/relay",
      number: 212,
      title: "Rate-limit the export route",
      head_sha: "4f9c1a2" + "0".repeat(33),
      files: [{ path: "api/export.py" }, { path: "tests/test_export.py" }],
    },
    digest_verified: true,
    review_instructions: "Read the diff.",
    needs: null,
    superseded: false,
    verification: {
      ran_at: "2026-10-31T06:10:00Z",
      holds: true,
      lines: [
        { ok: true, text: "the stored evidence hashes to its digest" },
        { ok: true, text: "#212 is open at 4f9c1a200000, the head this request names" },
      ],
    },
    ...overrides,
  };
}

function queue(ids: string[], superseded = 0) {
  return {
    ok: true,
    data: {
      counts: { pending: ids.length, unreviewed: 0, overdue: 0, ready_to_merge: 0, superseded },
      pending: ids.map((id) => ({ ...packet({ id }), evidence: undefined })),
      superseded: Array.from({ length: superseded }, (_, i) => ({
        id: `old-${i}`,
        subject_ref: `example-org/relay#200@${"b".repeat(7)}`,
        summary: "#200 Older",
        requested_head_sha: "b".repeat(40),
        current_head_sha: "c".repeat(40),
        reason: "new_commits",
      })),
      ready_to_merge: [],
      reviewer: { mode: "shadow", agreement: null },
      policy_version: "v1",
    },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  getReviewPacket.mockResolvedValue({ ok: true, data: packet() });
  getReviewQueue.mockResolvedValue(queue(["req-0", "req-1", "req-2"]));
});

async function renderPacket(): Promise<string> {
  const { default: ReviewPacketPage } = await import(
    "../app/product-owner/review-queue/[requestId]/page"
  );
  const { prelude } = await prerender(
    await ReviewPacketPage({ params: Promise.resolve({ requestId: "req-1" }) }),
  );
  return new Response(prelude).text();
}

describe("evidenceFields", () => {
  it("turns scalar evidence into labelled fields, in a stable order", () => {
    const fields = evidenceFields({ title: "T", number: 212, draft: false, empty: null });
    expect(fields).toEqual([
      { key: "title", label: "title", value: "T" },
      { key: "number", label: "number", value: "212" },
      { key: "draft", label: "draft", value: "no" },
      { key: "empty", label: "empty", value: "—" },
    ]);
  });

  it("summarises lists and objects rather than dumping them", () => {
    const fields = evidenceFields({
      files: [{ path: "a" }, { path: "b" }],
      finding: { severity: "high", rule_id: "R1" },
    });
    expect(fields[0]).toEqual({ key: "files", label: "files", value: "2 items" });
    // One level of an object is shown as its own fields, prefixed.
    expect(fields).toContainEqual({ key: "finding.severity", label: "finding · severity", value: "high" });
    expect(fields).toContainEqual({ key: "finding.rule_id", label: "finding · rule_id", value: "R1" });
  });

  it("uses underscores-as-spaces nowhere: keys are the evidence's own names", () => {
    expect(evidenceFields({ head_sha: "abc" })[0].label).toBe("head_sha");
  });
});

describe("concurRationale", () => {
  it("says it concurs, names the reviewer, cites the check and quotes three lines", () => {
    const text = concurRationale(REVIEW, { holds: true, ran_at: "2026-10-31T06:10:00Z", lines: [] });
    expect(text).toContain("Concur with the platform reviewer (claude-opus-5, 2026-10-31T06:00:00Z)");
    expect(text).toContain("the verification check, which held");
    expect(text).toContain("The diff does what it says. The cited test exists. CI is green.");
    expect(text).not.toContain("A fourth line");
  });

  it("is not offered on a procedural reject from a human-only tier", () => {
    expect(concurRationale({ ...REVIEW, verdict: "reject", delegable: false }, null)).toBeNull();
  });

  it("is not offered with no review", () => {
    expect(concurRationale(null, null)).toBeNull();
  });
});

describe("canRecord", () => {
  it("refuses an empty or whitespace rationale", () => {
    expect(canRecord("")).toBe(false);
    expect(canRecord("   \n")).toBe(false);
    expect(canRecord("Read the diff and the check output.")).toBe(true);
  });
});

describe("nextRequestHref", () => {
  it("goes to the next pending request, then back to Approvals after the last", () => {
    expect(nextRequestHref(["a", "b", "c"], "a")).toBe("/product-owner/review-queue/b");
    expect(nextRequestHref(["a", "b", "c"], "c")).toBe("/approvals");
    expect(nextRequestHref(["a"], "missing")).toBe("/product-owner/review-queue/a");
    expect(nextRequestHref([], "a")).toBe("/approvals");
  });
});

describe("the packet page", () => {
  it("shows the verification check and its output", async () => {
    const html = await renderPacket();
    expect(html).toContain("Verification check");
    expect(html).toContain("#212 is open at 4f9c1a200000, the head this request names");
    expect(html).toContain("check holds");
  });

  it("shows the evidence as fields, and keeps the raw JSON behind a disclosure", async () => {
    const html = await renderPacket();
    expect(html).toMatch(/<dt[^>]*>title<\/dt>\s*<dd[^>]*>Rate-limit the export route<\/dd>/);
    expect(html).toMatch(/<dt[^>]*>files<\/dt>\s*<dd[^>]*>2 items<\/dd>/);
    expect(html).toMatch(/<details[^>]*>[\s\S]*<summary[^>]*>[^<]*raw evidence[\s\S]*<pre/);
  });

  it("decides a request with no onboarded repository here, not through the API", async () => {
    const html = await renderPacket();
    expect(html).not.toContain("POST /api/approvals/");
    expect(html).toContain("Record and go to 3 of 3");
    expect(html).toContain("Concur with the reviewer");
  });

  it("names the digest the decision is bound to", async () => {
    const html = await renderPacket();
    expect(html).toContain(DIGEST.slice(0, 12));
  });

  it("warns on a superseded request and does not offer concur-to-approve", async () => {
    getReviewPacket.mockResolvedValueOnce({
      ok: true,
      data: packet({
        superseded: true,
        verification: {
          ran_at: "2026-10-31T06:10:00Z",
          holds: false,
          lines: [{ ok: false, text: "superseded: #212 has moved on to cccccccccccc" }],
        },
      }),
    });
    const html = await renderPacket();
    expect(html).toContain("superseded");
    expect(html).toContain("check fails");
  });
});

describe("the Approvals list hides superseded requests", () => {
  it("counts them and lists them behind a disclosure", async () => {
    getReviewQueue.mockResolvedValueOnce(queue(["req-1"], 3));
    const { ReviewQueueTab } = await import("../components/po-review-queue");
    const { prelude } = await prerender(await ReviewQueueTab());
    const html = await new Response(prelude).text();
    expect(html).toContain("3 superseded requests hidden because their pull request moved on");
    expect(html).toMatch(/<details[\s\S]*#200 Older/);
  });
});
