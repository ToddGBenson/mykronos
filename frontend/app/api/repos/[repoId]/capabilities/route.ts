/**
 * Proxy for capability enable/disable.
 *
 * Same shape and same reason as the finding-status proxy: the admin token
 * stays on this server, the client posts here, this attaches the credential.
 * The backend endpoint validates the set and — for Concourse-scanned repos —
 * syncs the ingestion grants immediately; for Actions repos it opens the
 * workflow-install PR. One button, both worlds.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function PATCH(
  request: Request,
  context: { params: Promise<{ repoId: string }> },
) {
  const { repoId } = await context.params;

  let body: { capabilities?: string[]; revoke_unlisted?: boolean };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: "Body must be JSON." }, { status: 400 });
  }

  if (!Array.isArray(body.capabilities)) {
    return NextResponse.json(
      { detail: "A capabilities list is required." },
      { status: 400 },
    );
  }

  try {
    const { data, error, response } = await backendClient().PATCH(
      "/api/repos/{repo_id}/capabilities",
      {
        params: { path: { repo_id: repoId } },
        body: {
          capabilities: body.capabilities as never,
          install_workflows: true,
          // Off unless the caller said so: a set built from what the
          // dashboard shows must not revoke a grant it never showed (B-062,
          // D-119). The backend answers 409 naming the grants instead, and
          // that detail is what the button renders.
          revoke_unlisted: body.revoke_unlisted === true,
        },
      },
    );

    if (!data) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the change." },
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
