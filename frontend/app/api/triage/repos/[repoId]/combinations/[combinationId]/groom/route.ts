/**
 * Proxy for grooming one detected toxic combination into a dev-ready story
 * (spec 17 §7.2). Repo-scoped because a combination id alone names no
 * repository — combinations are detected fresh, not stored (spec 08 §2).
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ repoId: string; combinationId: string }> },
) {
  const { repoId, combinationId } = await context.params;

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/triage/repos/{repo_id}/combinations/{combination_id}/groom",
      { params: { path: { repo_id: repoId, combination_id: combinationId } } },
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
