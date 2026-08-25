/**
 * Proxy for withdrawing a control (spec 28 §3).
 *
 * A control is a claim about the present, so withdrawing it deletes the row
 * rather than flagging it — nobody needs to know that somebody once believed
 * authentication was enforced. The backend's audit entry records who removed
 * it, which is the part that matters.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function DELETE(
  request: Request,
  context: { params: Promise<{ repoId: string; controlId: string }> },
) {
  const { repoId, controlId } = await context.params;

  try {
    const { error, response } = await backendClient().DELETE(
      "/api/dashboard/repos/{repo_id}/controls/{control_id}",
      { params: { path: { repo_id: repoId, control_id: controlId } } },
    );

    if (response.status >= 400) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the request." },
        { status: response.status },
      );
    }
    return new NextResponse(null, { status: 204 });
  } catch {
    return NextResponse.json(
      { detail: "Could not reach the Mykronos backend." },
      { status: 502 },
    );
  }
}
