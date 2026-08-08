/**
 * Proxy for the one write the dashboard performs.
 *
 * Exists so the admin token stays on the server. The Phase 1 auth stub is a
 * single bearer token with full admin rights — enough to offboard a repo — and
 * shipping that to the browser would put it one XSS away from anyone. The
 * client component posts here; this attaches the credential.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function PATCH(
  request: Request,
  context: { params: Promise<{ findingId: string }> },
) {
  const { findingId } = await context.params;

  let body: { status?: string; reason?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: "Body must be JSON." }, { status: 400 });
  }

  if (!body.status) {
    return NextResponse.json({ detail: "A status is required." }, { status: 400 });
  }

  try {
    const { data, error, response } = await backendClient().PATCH(
      "/api/dashboard/findings/{finding_id}/status",
      {
        params: { path: { finding_id: findingId } },
        body: { status: body.status as never, reason: body.reason ?? "" },
      },
    );

    if (!data) {
      // Pass the backend's own message through: it explains *why* — that
      // `fixed` is an observation, say — and rewriting it here would lose that.
      const detail =
        (error as { detail?: string } | undefined)?.detail ??
        `The API rejected the change (HTTP ${response?.status ?? "?"}).`;
      return NextResponse.json({ detail }, { status: response?.status ?? 502 });
    }

    return NextResponse.json(data);
  } catch (cause) {
    return NextResponse.json(
      {
        detail:
          cause instanceof Error && /fetch failed|ECONNREFUSED/i.test(cause.message)
            ? "Cannot reach the Mykronos API."
            : "Unexpected error talking to the Mykronos API.",
      },
      { status: 502 },
    );
  }
}
