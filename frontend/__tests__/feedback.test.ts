/**
 * Feedback goes to TheHub, never to a public GitHub issue (TheHub #61132).
 *
 * The button used to open a pre-filled `issues/new` on the platform's public
 * repository, one click from publishing whatever the operator typed. Now the
 * dialog posts to this server's `/api/feedback`, which forwards it with the
 * admin token to the backend, which files a TheHub story with the Hub token
 * it holds. With no Hub, the dialog says feedback is unavailable and offers
 * nothing else.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("next/navigation", () => ({ usePathname: () => "/repos/r-1/findings" }));

const GET = vi.fn();
const POST = vi.fn();
vi.mock("@/lib/api", () => ({ backendClient: () => ({ GET, POST }) }));

import * as route from "@/app/api/feedback/route";
import { FeedbackView } from "@/components/feedback";
import {
  BLANK_DRAFT,
  FEEDBACK_ROUTE,
  draftProblem,
  feedbackBody,
  type FeedbackPhase,
} from "@/lib/feedback";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.(ts|tsx)$/.test(name) && !name.endsWith(".d.ts") ? [path] : [];
  });
}

function render(phase: FeedbackPhase, open = true): string {
  return renderToStaticMarkup(
    createElement(FeedbackView, {
      open,
      phase,
      draft: { ...BLANK_DRAFT, summary: "The filter is lost" },
      onChange: () => undefined,
      onSubmit: () => undefined,
      onClose: () => undefined,
    }),
  );
}

describe("the target", () => {
  it("is no GitHub issue anywhere in the frontend", () => {
    const offenders = ["app", "components", "lib"]
      .flatMap((dir) => sources(join(ROOT, dir)))
      .filter((path) => /issues\/new/.test(readFileSync(path, "utf8")));

    expect(offenders).toEqual([]);
  });

  it("is this server's own route, so the token stays here", () => {
    expect(FEEDBACK_ROUTE).toBe("/api/feedback");
  });

  it("is forwarded to the backend's feedback route", async () => {
    POST.mockResolvedValue({
      data: { story_id: 70001 },
      error: undefined,
      response: new Response(null, { status: 201 }),
    });

    const response = await route.POST(
      new Request("http://dashboard.test/api/feedback", {
        method: "POST",
        body: JSON.stringify(feedbackBody({ ...BLANK_DRAFT, summary: "abc" }, "/x", "0.1.0")),
      }),
    );

    expect(POST).toHaveBeenCalledTimes(1);
    expect(POST.mock.calls[0][0]).toBe("/api/feedback");
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({ story_id: 70001 });
  });

  it("passes the backend's 503 through, with no fallback", async () => {
    POST.mockResolvedValue({
      data: undefined,
      error: { detail: "Feedback is unavailable: TheHub is not connected." },
      response: new Response(null, { status: 503 }),
    });

    const response = await route.POST(
      new Request("http://dashboard.test/api/feedback", { method: "POST", body: "{}" }),
    );

    expect(response.status).toBe(503);
    expect((await response.json()).detail).toMatch(/Feedback is unavailable/);
  });

  it("asks the backend whether feedback is available", async () => {
    GET.mockResolvedValue({
      data: { available: false, reason: "TheHub is not connected." },
      error: undefined,
      response: new Response(null, { status: 200 }),
    });

    const response = await route.GET();

    expect(GET.mock.calls[0][0]).toBe("/api/feedback");
    expect(await response.json()).toEqual({ available: false, reason: "TheHub is not connected." });
  });
});

describe("the dialog", () => {
  beforeEach(() => {
    GET.mockReset();
    POST.mockReset();
  });

  it("renders nothing while closed", () => {
    expect(render({ kind: "ready" }, false)).toBe("");
  });

  it("says plainly that feedback is unavailable, and offers no way to send", () => {
    const html = render({ kind: "unavailable", reason: "TheHub is not connected." });

    expect(html).toContain("Feedback is unavailable");
    expect(html).toContain("TheHub is not connected.");
    expect(html).not.toContain('type="submit"');
    expect(html).not.toMatch(/github/i);
  });

  it("is a labelled modal dialog with a labelled form when available", () => {
    const html = render({ kind: "ready" });

    expect(html).toContain('role="dialog"');
    expect(html).toContain('aria-modal="true"');
    expect(html).toMatch(/aria-labelledby="[^"]+"/);
    expect(html).toContain('type="submit"');
    expect(html).toMatch(/<label[^>]*for="feedback-summary"/);
    expect(html).toMatch(/<label[^>]*for="feedback-detail"/);
  });

  it("names the story it filed", () => {
    const html = render({ kind: "filed", storyId: 70001 });

    expect(html).toContain("TheHub story #70001");
    expect(html).not.toContain('type="submit"');
  });

  it("shows a failure in an alert", () => {
    const html = render({ kind: "failed", message: "TheHub refused: title too short" });

    expect(html).toContain('role="alert"');
    expect(html).toContain("title too short");
  });
});

describe("the report", () => {
  it("carries the kind, the text, the page and the release, and nothing else", () => {
    const body = feedbackBody(
      { kind: "feature", summary: "  Export to CSV  ", detail: "please" },
      "/findings",
      "0.1.0",
    );

    expect(body).toEqual({
      kind: "feature",
      summary: "Export to CSV",
      detail: "please",
      page: "/findings",
      release: "0.1.0",
    });
  });

  it("needs a summary of three characters, and caps both fields", () => {
    expect(draftProblem({ ...BLANK_DRAFT, summary: "ab" })).toMatch(/summary/i);
    expect(draftProblem({ ...BLANK_DRAFT, summary: "x".repeat(201) })).toMatch(/200/);
    expect(draftProblem({ ...BLANK_DRAFT, summary: "abc", detail: "y".repeat(4001) })).toMatch(
      /4,000/,
    );
    expect(draftProblem({ ...BLANK_DRAFT, summary: "abc" })).toBeNull();
  });
});
