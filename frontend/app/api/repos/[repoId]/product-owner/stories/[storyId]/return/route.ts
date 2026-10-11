/** Proxy for moving a sprint story back to the backlog (spec 35 §4). */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  _request: Request,
  context: { params: Promise<{ repoId: string; storyId: string }> },
) {
  const { repoId, storyId } = await context.params;
  const id = Number(storyId);
  if (!Number.isInteger(id) || id < 1) {
    return NextResponse.json({ detail: "Not a story id." }, { status: 400 });
  }

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/repos/{repo_id}/product-owner/stories/{story_id}/return",
      { params: { path: { repo_id: repoId, story_id: id } } },
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
