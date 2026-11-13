/**
 * The Today run sheet's actions (TheHub #61142), shipped switched off.
 *
 * Operator decision 2026-11-04: Merge in order, Deploy and the Decide drawer
 * are built now and turned on after 11-08 at the earliest. The switch is a
 * server environment variable on the Next server (the browser cannot set it)
 * AND the backend's `runsheet_actions_enabled`. While either is off, /today
 * renders as 3a did and the proxy routes answer 404 without calling the
 * backend.
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const POST = vi.fn();

vi.mock("server-only", () => ({}));
vi.mock("@/lib/api", () => ({
  BackendUnavailable: class extends Error {},
  backendClient: () => ({ POST }),
}));
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: () => {}, refresh: () => {} }),
}));

import { POST as deployPOST } from "@/app/api/today/deploy/route";
import { POST as mergePOST } from "@/app/api/today/merge/route";
import { DecideDrawerView } from "@/components/decide-drawer";
import { DeployAction, MergeInOrder } from "@/components/runsheet-actions";
import {
  ACTIONS_ENV,
  actionsOn,
  crossOriginRefusal,
  decideHref,
  mergeBatch,
  showActions,
} from "@/lib/runsheet-actions";

const THEHUB = "ToddGBenson/TheHub";
const MK = "ToddGBenson/mykronos";
const A = "a".repeat(40);
const B = "b".repeat(40);

import type { ItemLike } from "@/lib/today";

function item(ref: string, sha: string, state: ItemLike["state"] = "ready"): ItemLike {
  return { text: `${ref}: a change`, state, reason: "approved", owner: "you", ref, url: "", sha };
}

describe("the switch", () => {
  it("is off unless the server environment says exactly on", () => {
    expect(actionsOn({})).toBe(false);
    expect(actionsOn({ [ACTIONS_ENV]: "true" })).toBe(false);
    expect(actionsOn({ [ACTIONS_ENV]: "1" })).toBe(false);
    expect(actionsOn({ [ACTIONS_ENV]: "on" })).toBe(true);
  });

  it("needs the backend's flag too", () => {
    expect(showActions({ [ACTIONS_ENV]: "on" }, false)).toBe(false);
    expect(showActions({ [ACTIONS_ENV]: "on" }, undefined)).toBe(false);
    expect(showActions({}, true)).toBe(false);
    expect(showActions({ [ACTIONS_ENV]: "on" }, true)).toBe(true);
  });
});

describe("the merge batch", () => {
  it("takes the ready pull requests, TheHub first, at the heads shown", () => {
    const { batch } = mergeBatch([
      item(`${MK}#9`, A),
      item(`${MK}#3`, B, "blocked"),
      item(`${THEHUB}#20`, B),
    ]);

    expect(batch).toEqual([
      { repo_full_name: THEHUB, number: 20, head_sha: B },
      { repo_full_name: MK, number: 9, head_sha: A },
    ]);
  });

  it("is at most five, and says what it left for the next batch", () => {
    const items = [1, 2, 3, 4, 5, 6, 7].map((n) => item(`${MK}#${n}`, A));

    const { batch, left } = mergeBatch(items);

    expect(batch.map((p) => p.number)).toEqual([1, 2, 3, 4, 5]);
    expect(left).toBe(2);
  });

  it("never offers a line without a head", () => {
    expect(mergeBatch([item(`${MK}#1`, "")]).batch).toEqual([]);
  });
});

describe("the buttons", () => {
  it("merge in order names the order and waits for the host-guard acknowledgement", () => {
    const html = renderToStaticMarkup(
      createElement(MergeInOrder, {
        batch: [
          { repo_full_name: THEHUB, number: 20, head_sha: B },
          { repo_full_name: MK, number: 9, head_sha: A },
        ],
        left: 0,
        notes: ["The deploy lock is the host's to check."],
      }),
    );

    expect(html).toContain("Merge 2 in order");
    expect(html.indexOf(`${THEHUB}#20`)).toBeLessThan(html.indexOf(`${MK}#9`));
    expect(html).toMatch(/<input[^>]*type="checkbox"[^>]*id="merge-ack"/);
    expect(html).toContain('for="merge-ack"');
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Merge 2 in order/);
    expect(html).toContain("The deploy lock is the host&#x27;s to check.");
  });

  it("renders no merge button when nothing is ready", () => {
    expect(
      renderToStaticMarkup(createElement(MergeInOrder, { batch: [], left: 0, notes: [] })),
    ).toBe("");
  });

  it("deploy names the sha it will deploy", () => {
    const html = renderToStaticMarkup(createElement(DeployAction, { sha: A, notes: [] }));

    expect(html).toContain(`Deploy ${A.slice(0, 12)}`);
    expect(html).toMatch(/<button[^>]*disabled=""/);
  });
});

describe("the decide drawer", () => {
  const packet = {
    id: "req-1",
    duty: "pull_request_merge",
    tier: "T2",
    subject_ref: `${MK}#9@${A}`,
    repo_full_name: MK,
    requested_by: "agent:builder",
    requester_kind: "agent",
    summary: "Merge the export rate limit",
    evidence_digest: "f".repeat(64),
    digest_verified: true,
    superseded: false,
    reviewer: { verdict: "approve", rationale: "Tests cover it.", checks: [], model: "fable" },
    verification: { holds: true, lines: [] },
    decisions: [],
    needs: null,
    evidence: {},
    expires_at: null,
    overdue: false,
  };

  it("is the 1b packet's decision, with the full packet one link away", () => {
    const html = renderToStaticMarkup(
      createElement(DecideDrawerView, {
        packet: packet as never,
        nextHref: "/today",
        nextLabel: "",
      }),
    );

    expect(html).toContain('aria-labelledby="decide-drawer-title"');
    expect(html).toContain("pull_request_merge · T2");
    expect(html).toContain("check holds");
    expect(html).toContain("digest verified");
    expect(html).toContain('href="/product-owner/review-queue/req-1"');
    expect(html).toContain('href="/today"');
    expect(html).toContain("Approve");
  });

  it("opens from a decide line by its request id", () => {
    expect(decideHref("req 1")).toBe("/today?decide=req%201");
  });
});

describe("the proxy routes", () => {
  const before = process.env[ACTIONS_ENV];
  beforeEach(() => POST.mockReset());
  afterEach(() => {
    if (before === undefined) delete process.env[ACTIONS_ENV];
    else process.env[ACTIONS_ENV] = before;
  });

  function request(body: unknown): Request {
    return new Request("http://dashboard.test/api/today/merge", {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
  }

  it.each([
    ["merge", mergePOST],
    ["deploy", deployPOST],
  ])("%s is a 404 while switched off, and never reaches the backend", async (_name, handler) => {
    delete process.env[ACTIONS_ENV];

    const response = await handler(request({}));

    expect(response.status).toBe(404);
    expect(POST).not.toHaveBeenCalled();
  });

  it("merge forwards the batch to the backend when on", async () => {
    process.env[ACTIONS_ENV] = "on";
    POST.mockResolvedValue({
      data: { id: "r1", state: "queued", outcomes: [], notes: [] },
      response: { status: 202 },
    });
    const body = {
      pull_requests: [{ repo_full_name: MK, number: 9, head_sha: A }],
      acknowledged_host_guards: true,
    };

    const response = await mergePOST(request(body));

    expect(response.status).toBe(202);
    expect(POST).toHaveBeenCalledWith("/api/dashboard/today/merge", { body });
  });

  it("passes a refusal through with its status", async () => {
    process.env[ACTIONS_ENV] = "on";
    POST.mockResolvedValue({
      error: { detail: { reason: "refused", outcomes: [] } },
      response: { status: 409 },
    });

    const response = await deployPOST(request({ sha: A, acknowledged_host_guards: true }));

    expect(response.status).toBe(409);
  });
});

describe("the cross-origin guard", () => {
  function headers(extra: Record<string, string>): Headers {
    return new Headers({ "content-type": "application/json", host: "dash.test", ...extra });
  }

  it("lets a same-origin JSON request through", () => {
    expect(crossOriginRefusal(headers({ "sec-fetch-site": "same-origin" }))).toBeNull();
    expect(crossOriginRefusal(headers({ origin: "https://dash.test" }))).toBeNull();
  });

  it("refuses a form post, a same-site sibling and a foreign origin", () => {
    expect(crossOriginRefusal(new Headers({ "content-type": "text/plain" }))).toMatch(/JSON/);
    expect(crossOriginRefusal(headers({ "sec-fetch-site": "same-site" }))).toMatch(/refused/);
    expect(crossOriginRefusal(headers({ origin: "https://demo.dash.test" }))).toMatch(/refused/);
  });

  it("refuses at the route before the backend is called", async () => {
    process.env[ACTIONS_ENV] = "on";
    POST.mockReset();
    const response = await mergePOST(
      new Request("http://dash.test/api/today/merge", {
        method: "POST",
        body: "{}",
        headers: headers({ "sec-fetch-site": "cross-site" }),
      }),
    );
    delete process.env[ACTIONS_ENV];

    expect(response.status).toBe(403);
    expect(POST).not.toHaveBeenCalled();
  });
});
