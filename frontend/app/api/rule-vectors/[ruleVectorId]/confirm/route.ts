/**
 * Proxy for confirming a rule vector (TheHub #60832).
 *
 * Its own action rather than an edit, because what is recorded is that a
 * person looked: the backend refuses an agent's credential here, and this
 * server holds the operator's. A `vector` in the body is the proposal edited
 * before confirming.
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
      "/api/dashboard/rule-vectors/{rule_vector_id}/confirm",
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
