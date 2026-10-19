/**
 * Proxy for retiring a rule vector (TheHub #60832): a proposal withdrawn, or
 * a confirmed vector withdrawn so its findings go back to unscored.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ ruleVectorId: string }> },
) {
  const { ruleVectorId } = await context.params;
  const body = (await request.json()) as Record<string, unknown>;

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/rule-vectors/{rule_vector_id}/retire",
      { params: { path: { rule_vector_id: ruleVectorId } }, body: body as never },
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
