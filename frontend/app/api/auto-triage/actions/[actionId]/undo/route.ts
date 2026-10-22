/**
 * Proxy for undoing one auto-triage action (TheHub #60888).
 * Same shape and same reason as every other proxy here: the admin token stays
 * on this server.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ actionId: string }> },
) {
  const { actionId } = await context.params;

  let body: { reason?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: "Body must be JSON." }, { status: 400 });
  }

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/auto-triage/actions/{action_id}/undo",
      {
        params: { path: { action_id: actionId } },
        body: { reason: body.reason ?? "" },
      },
    );
    if (!data) {
      // A 409 says the finding changed since the action, or it was already
      // undone; the person needs to read which.
      const detail =
        (error as { detail?: string } | undefined)?.detail ??
        `The API refused the undo (HTTP ${response?.status ?? "?"}).`;
      return NextResponse.json({ detail }, { status: response?.status ?? 502 });
    }
    return NextResponse.json(data);
  } catch {
    return NextResponse.json(
      { detail: "Could not reach the Mykronos backend." },
      { status: 502 },
    );
  }
}
