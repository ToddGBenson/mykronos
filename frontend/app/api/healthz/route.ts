/**
 * Is this Next.js server running?
 *
 * That question and *is the whole platform working* are different, and the
 * container healthcheck used to ask the second one. It fetched `/` — the
 * portfolio page, which is `force-dynamic` with `cache: "no-store"` and calls
 * the backend on every render — so the check exercised Next.js, the backend,
 * and a DuckDB portfolio aggregate before it would answer.
 *
 * Two things went wrong with that on 2026-08-25. Under CI load the page took
 * 3–10s against a 5s healthcheck timeout, so the container reported
 * `unhealthy` while returning 200s to every request. And it meant a backend
 * blip would mark the *frontend* unhealthy — which is the backend
 * healthcheck's job to report, from the container that can actually do
 * something about it.
 *
 * So this endpoint deliberately touches nothing. No backend call, no data, no
 * imports beyond the response. If this answers, the Node process is up and
 * routing works, which is the entire claim a container healthcheck should
 * make about itself.
 */

// Never prerendered or cached: a health endpoint served from a build-time
// cache would answer 200 from a process that had stopped working, which is
// precisely the failure it exists to detect.
export const dynamic = "force-dynamic";

export function GET() {
  return new Response("ok", {
    status: 200,
    headers: { "content-type": "text/plain", "cache-control": "no-store" },
  });
}
