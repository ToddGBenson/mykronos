/**
 * Proxy for deciding any approval request from its review packet (TheHub
 * #61136), estate-wide ones included. The backend runs the verification check
 * again, hands the decision to the spec 34 approvals engine and stores the
 * check with the decision; this only forwards, so the admin token stays on
 * this server. A refusal is passed through as the engine wrote it.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ requestId: string }> },
) {
  const { requestId } = await context.params;
  const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body) {
    return NextResponse.json({ detail: "Expected a JSON body." }, { status: 400 });
  }

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/product-owner/approvals/{request_id}/decision",
      {
        params: { path: { request_id: requestId } },
        body: body as never,
      },
    );
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
