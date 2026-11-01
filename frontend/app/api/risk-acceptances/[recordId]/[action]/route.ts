/**
 * Proxy for the three things a person does to a live risk acceptance
 * (TheHub #61140): renew it, revoke it, or record its interim review.
 *
 * Only those three paths are forwarded. Each backend route validates its own
 * body, and revoke and interim review require a person.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

const ACTIONS = ["renew", "revoke", "interim-review"] as const;
type Action = (typeof ACTIONS)[number];

function forward(action: Action, recordId: string, body: never) {
  const client = backendClient();
  const params = { path: { record_id: recordId } };
  if (action === "renew") {
    return client.POST("/api/risk-acceptances/{record_id}/renew", { params, body });
  }
  if (action === "revoke") {
    return client.POST("/api/risk-acceptances/{record_id}/revoke", { params, body });
  }
  return client.POST("/api/risk-acceptances/{record_id}/interim-review", { params, body });
}

export async function POST(
  request: Request,
  context: { params: Promise<{ recordId: string; action: string }> },
) {
  const { recordId, action } = await context.params;
  if (!(ACTIONS as readonly string[]).includes(action)) {
    return NextResponse.json({ detail: `No action ${action}.` }, { status: 404 });
  }
  const body = await request.json().catch(() => null);
  if (body === null) {
    return NextResponse.json({ detail: "A JSON body is required." }, { status: 422 });
  }

  try {
    const { data, error, response } = await forward(action as Action, recordId, body as never);
    if (!data) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the request." },
        { status: response.status },
      );
    }
    return NextResponse.json(data);
  } catch {
    return NextResponse.json(
      { detail: "Could not reach the Mykronos backend." },
      { status: 502 },
    );
  }
}
