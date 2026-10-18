/**
 * Proxy for re-reading `.sdlc/threat-model.yaml` now (TheHub #60825). Same
 * shape and same reason as every other proxy here: the admin token stays on
 * this server.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  _request: Request,
  context: { params: Promise<{ repoId: string }> },
) {
  const { repoId } = await context.params;

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/repos/{repo_id}/threat-model/sync",
      { params: { path: { repo_id: repoId } } },
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
