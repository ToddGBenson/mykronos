/**
 * Proxy for declaring an asset, entry point or trust boundary (B-029).
 * Same shape and same reason as every other proxy here: the admin token stays
 * on this server.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ repoId: string }> },
) {
  const { repoId } = await context.params;
  const body = (await request.json()) as Record<string, unknown>;

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/repos/{repo_id}/surfaces",
      {
        params: { path: { repo_id: repoId } },
        body: body as never,
      },
    );

    if (!data) {
      // The backend's own message is the useful one: a 422 names the
      // vocabulary the value was not in, which is what the person needs.
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
