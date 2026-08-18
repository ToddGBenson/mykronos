/**
 * Proxy for on-demand scan dispatch (spec 17 §2.5).
 *
 * Same shape and same reason as the capability-toggle proxy: the admin token
 * stays on this server. The backend endpoint branches on `scanned_by` —
 * GitHub Actions `workflow_dispatch` or a Concourse build trigger — and this
 * route doesn't need to know which; it only forwards the result.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ repoId: string }> },
) {
  const { repoId } = await context.params;

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/repos/{repo_id}/scan",
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
