/**
 * Proxy for proposing a risk acceptance (TheHub #61140, spec 33).
 *
 * The proposal opens its own approval request; nothing is accepted until a
 * person independent of the requester approves it. The admin token stays on
 * this server.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  if (body === null) {
    return NextResponse.json({ detail: "A JSON body is required." }, { status: 422 });
  }

  try {
    const { data, error, response } = await backendClient().POST("/api/risk-acceptances", {
      body,
    });

    if (!data) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the request." },
        { status: response.status },
      );
    }
    return NextResponse.json(data, { status: 201 });
  } catch {
    return NextResponse.json(
      { detail: "Could not reach the Mykronos backend." },
      { status: 502 },
    );
  }
}
