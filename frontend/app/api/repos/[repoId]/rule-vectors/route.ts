/**
 * Proxy for proposing a rule vector (TheHub #60832). A proposal changes no
 * score; it is the first step, and a person's confirmation is the second.
 * `estate: true` proposes for every repository rather than this one.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ repoId: string }> },
) {
  const { repoId } = await context.params;
  const { estate, ...body } = (await request.json()) as Record<string, unknown>;

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/rule-vectors",
      { body: { ...body, ...(estate ? {} : { repo_id: repoId }) } as never },
    );

    if (!data) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the request." },
        { status: response.status },
      );
    }
    return NextResponse.json(data, { status: 201 });
  } catch {
    return NextResponse.json(
      { detail: "Could not reach the Mykronos backend." },
      { status: 502 },
    );
  }
}
