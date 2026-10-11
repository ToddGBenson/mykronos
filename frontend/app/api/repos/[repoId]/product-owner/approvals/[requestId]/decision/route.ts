/**
 * Proxy for deciding an approval request from the Product Owner console
 * (spec 35 §8.2, D-137). The backend hands the decision to the spec 34
 * approvals engine; this only forwards, so the admin token stays on this
 * server. A refusal is passed through as the engine wrote it.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ repoId: string; requestId: string }> },
) {
  const { repoId, requestId } = await context.params;
  const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body) {
    return NextResponse.json({ detail: "Expected a JSON body." }, { status: 400 });
  }

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/repos/{repo_id}/product-owner/approvals/{request_id}/decision",
      {
        params: { path: { repo_id: repoId, request_id: requestId } },
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
