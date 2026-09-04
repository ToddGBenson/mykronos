/** Proxy for withdrawing a declaration (B-029). A correction, not a deletion
 *  of evidence — which is why this register is operational rather than in the
 *  append-only lake. */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function DELETE(
  request: Request,
  context: { params: Promise<{ repoId: string; surfaceId: string }> },
) {
  const { repoId, surfaceId } = await context.params;

  try {
    const { error, response } = await backendClient().DELETE(
      "/api/dashboard/repos/{repo_id}/surfaces/{surface_id}",
      { params: { path: { repo_id: repoId, surface_id: surfaceId } } },
    );

    // 204 carries no body, so an absent `data` is the success case here and
    // the status is what decides.
    if (response.status === 204) {
      return new NextResponse(null, { status: 204 });
    }
    return NextResponse.json(
      (error as object) ?? { detail: "The backend refused the request." },
      { status: response.status },
    );
  } catch {
    return NextResponse.json(
      { detail: "Could not reach the Mykronos backend." },
      { status: 502 },
    );
  }
}
