/**
 * Proxy for pulling a story into the sprint (spec 35 §4). The backend switches
 * the story's autonomy off first and moves it second; this only forwards, so
 * the admin token stays on this server like every other proxy here.
 */

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
      "/api/dashboard/repos/{repo_id}/product-owner/stories/{story_id}/pull",
      { params: { path: { repo_id: repoId, story_id: id } } },
    );
    if (!data) {
      // TheHub's refusal, carried through the backend verbatim: it says which
      // of its rules the story does not meet, which is what the person needs.
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
