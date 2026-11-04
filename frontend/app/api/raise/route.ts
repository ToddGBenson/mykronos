/**
 * Proxy for raising a Hub incident or story (TheHub #60911). This server
 * holds the credential; the browser never does. The backend builds the
 * evidence and audits who raised it.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(request: Request) {
  const body = (await request.json()) as Record<string, unknown>;
  try {
    const { data, error, response } = await backendClient().POST("/api/dashboard/raise", {
      body: body as never,
    });
    if (!data) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the request." },
        { status: response.status },
      );
    }
    return NextResponse.json(data, { status: 201 });
  } catch {
    return NextResponse.json({ detail: "Could not reach the Mykronos backend." }, { status: 502 });
  }
}
