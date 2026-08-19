/**
 * Proxy for overriding a risk decision (spec 21 §4).
 *
 * The endpoint has worked, audited and reason-mandatory, since spec 09 — with
 * no way to reach it that did not involve knowing the URL. Nothing about its
 * contract changes here (one-shot, 409 if already overridden); this is the
 * button.
 *
 * Backend errors are passed through verbatim rather than flattened to a
 * generic failure: 409 "already overridden" and 404 "no such decision" tell a
 * person two different things to do next.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ decisionId: string }> },
) {
  const { decisionId } = await context.params;
  const body = await request.json().catch(() => null);
  if (body === null) {
    return NextResponse.json({ detail: "A JSON body is required." }, { status: 422 });
  }

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/oracle/decisions/{decision_id}/override",
      { params: { path: { decision_id: decisionId } }, body },
    );

    if (!data) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the override." },
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
