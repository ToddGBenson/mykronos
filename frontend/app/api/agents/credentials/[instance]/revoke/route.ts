/**
 * Proxy for revoking an agent credential (TheHub #61144, spec 34 §1).
 *
 * Revocation is a person's act (`HumanDep` on the backend), and it takes every
 * descendant with it. The browser never holds the token; this server does.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  _request: Request,
  context: { params: Promise<{ instance: string }> },
) {
  const { instance } = await context.params;

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/agents/credentials/{instance}/revoke",
      { params: { path: { instance } } },
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
