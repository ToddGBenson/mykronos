/**
 * The raise and feedback write proxies (TheHub #61379, #61386).
 *
 * Both take a browser's POST and attach this server's credential, so each
 * must refuse a request the browser marks as cross-origin before it reaches
 * the backend, and answer malformed JSON with a 400 rather than a Next 500.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const POST = vi.fn();

vi.mock("server-only", () => ({}));
vi.mock("@/lib/api", () => ({
  BackendUnavailable: class extends Error {},
  backendClient: () => ({ POST }),
}));

import { POST as feedbackPOST } from "@/app/api/feedback/route";
import { POST as raisePOST } from "@/app/api/raise/route";
import { crossOriginRefusal } from "@/lib/same-origin";

const ROUTES = [
  ["/api/raise", raisePOST, { kind: "lane", subject: "o/r:sast", raise_as: "incident" }],
  ["/api/feedback", feedbackPOST, { kind: "bug", summary: "A thing is wrong", page: "/" }],
] as const;

function post(path: string, body: string, extra: Record<string, string> = {}): Request {
  return new Request(`http://dash.test${path}`, {
    method: "POST",
    body,
    headers: { "content-type": "application/json", host: "dash.test", ...extra },
  });
}

beforeEach(() => POST.mockReset());

describe.each(ROUTES)("%s", (path, handler, good) => {
  it("answers malformed JSON with a 400 and never calls the backend", async () => {
    const response = await handler(post(path, "{not json"));

    expect(response.status).toBe(400);
    expect(((await response.json()) as { detail: string }).detail).toMatch(/JSON/);
    expect(POST).not.toHaveBeenCalled();
  });

  it("refuses a cross-origin POST before the backend is called", async () => {
    const attempts: Record<string, string>[] = [
      { "sec-fetch-site": "cross-site" },
      { "sec-fetch-site": "same-site" },
      { origin: "https://evil.example" },
    ];
    for (const extra of attempts) {
      const response = await handler(post(path, JSON.stringify(good), extra));
      expect(response.status).toBe(403);
    }
    expect(POST).not.toHaveBeenCalled();
  });

  it("refuses a body that is not declared JSON (a cross-site form post)", async () => {
    const response = await handler(
      post(path, JSON.stringify(good), { "content-type": "text/plain" }),
    );

    expect(response.status).toBe(403);
    expect(POST).not.toHaveBeenCalled();
  });

  it("forwards a same-origin POST and passes the backend's refusal through", async () => {
    POST.mockResolvedValueOnce({
      data: { hub_id: 1, story_id: 1 },
      response: { status: 201 },
    });
    const ok = await handler(
      post(path, JSON.stringify(good), { "sec-fetch-site": "same-origin", origin: "http://dash.test" }),
    );
    expect(ok.status).toBe(201);
    expect(POST).toHaveBeenCalledTimes(1);

    POST.mockResolvedValueOnce({
      error: { detail: "At most 20 per hour." },
      response: { status: 429 },
    });
    const limited = await handler(post(path, JSON.stringify(good)));
    expect(limited.status).toBe(429);
    expect(((await limited.json()) as { detail: string }).detail).toMatch(/hour/);
  });
});

describe("the shared guard", () => {
  it("is the one the run sheet's routes use", async () => {
    const runsheet = await import("@/lib/runsheet-actions");
    expect(runsheet.crossOriginRefusal).toBe(crossOriginRefusal);
  });
});
