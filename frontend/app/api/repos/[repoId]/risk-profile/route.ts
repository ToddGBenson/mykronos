/**
 * Proxy for recording a repository's risk profile (spec 21 §1.3).
 * Same shape and same reason as every other proxy here: the admin token
 * stays on this server.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function PUT(
  request: Request,
  context: { params: Promise<{ repoId: string }> },
) {
  const { repoId } = await context.params;
  const body = await request.json().catch(() => null);
  if (body === null) {
    return NextResponse.json({ detail: "A JSON body is required." }, { status: 422 });
  }

  try {
    const { data, error, response } = await backendClient().PUT(
      "/api/repos/{repo_id}/risk-profile",
      { params: { path: { repo_id: repoId } }, body },
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
