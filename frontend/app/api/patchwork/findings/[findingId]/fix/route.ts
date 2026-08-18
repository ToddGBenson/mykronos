/**
 * Proxy for actually generating a fix and opening the draft PR for one
 * finding (spec 18 §7.2). Same shape as every other proxy here: the admin
 * token stays on this server.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ findingId: string }> },
) {
  const { findingId } = await context.params;

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/patchwork/findings/{finding_id}/fix",
      { params: { path: { finding_id: findingId } } },
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
