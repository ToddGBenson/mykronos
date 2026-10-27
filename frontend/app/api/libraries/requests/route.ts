/**
 * Proxy for requesting a library (TheHub #60895).
 *
 * The backend vets the package (OSV, deps.dev, Scorecard, typosquat and
 * new-package checks) and opens its approval request; this server holds the
 * credential, the browser never does.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(request: Request) {
  const body = (await request.json()) as Record<string, unknown>;

  try {
    const { data, error, response } = await backendClient().POST("/api/libraries/requests", {
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
    return NextResponse.json(
      { detail: "Could not reach the Mykronos backend." },
      { status: 502 },
    );
  }
}
