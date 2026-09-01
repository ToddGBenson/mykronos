/**
 * Proxy for confirming or rejecting what the classifier concluded (B-020).
 * Same shape and same reason as every other proxy here: the admin token stays
 * on this server.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ findingId: string }> },
) {
  const { findingId } = await context.params;
  const body = (await request.json()) as { agrees?: boolean; reason?: string };

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/findings/{finding_id}/classification-review",
      {
        params: { path: { finding_id: findingId } },
        body: { agrees: Boolean(body.agrees), reason: body.reason ?? "" },
      },
    );

    if (!data) {
      // The backend's own message is the useful one here — a 409 says the
      // finding was not the classifier's to dismiss, and a 422 says the
      // reason was missing. Both are things the person needs to read.
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
