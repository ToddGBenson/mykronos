/**
 * Proxy for confirming a control is still true (spec 28 §3).
 *
 * Its own action rather than an edit, because what is being recorded is that
 * a person looked. A mitigation nobody has checked since last quarter is a
 * belief, and the tab has to be able to say which of the two it is showing.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ repoId: string; controlId: string }> },
) {
  const { repoId, controlId } = await context.params;

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/repos/{repo_id}/controls/{control_id}/confirm",
      { params: { path: { repo_id: repoId, control_id: controlId } } },
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
