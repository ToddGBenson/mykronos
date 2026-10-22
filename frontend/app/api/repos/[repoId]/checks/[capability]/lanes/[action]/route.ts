/**
 * Proxy for retiring a scan lane on purpose, or restoring one (TheHub #60816).
 * The backend refuses anyone but a person, and audits both.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

const PATHS = {
  retire: "/api/dashboard/repos/{repo_id}/checks/{capability}/lanes/retire",
  restore: "/api/dashboard/repos/{repo_id}/checks/{capability}/lanes/restore",
} as const;

export async function POST(
  request: Request,
  context: { params: Promise<{ repoId: string; capability: string; action: string }> },
) {
  const { repoId, capability, action } = await context.params;
  if (action !== "retire" && action !== "restore") {
    return NextResponse.json({ detail: `Unknown lane action '${action}'.` }, { status: 404 });
  }
  const body = (await request.json()) as Record<string, unknown>;

  try {
    const { data, error, response } = await backendClient().POST(PATHS[action], {
      params: { path: { repo_id: repoId, capability } },
      body: body as never,
    });
    if (!data) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the request." },
        { status: response.status },
      );
    }
    return NextResponse.json(data);
  } catch {
    return NextResponse.json({ detail: "Could not reach the Mykronos backend." }, { status: 502 });
  }
}
