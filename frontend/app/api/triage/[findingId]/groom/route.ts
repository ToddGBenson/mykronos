/**
 * Proxy for grooming one finding into a dev-ready story (spec 17 §7.2).
 * Same shape and same reason as every other proxy here: the admin token
 * stays on this server.
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
      "/api/triage/{finding_id}/groom",
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
