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

  let body: { capabilities?: string[] };
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
