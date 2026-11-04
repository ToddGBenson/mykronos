/**
 * Proxy for the run sheet's deploy action (TheHub #61142), switched off by default.
 *
 * A 404 unless this Next server's environment has `MYKRONOS_RUNSHEET_ACTIONS=on`:
 * the browser cannot set it, and while it is off the backend is never called.
 * When on, the backend still refuses unless its own `runsheet_actions_enabled`
 * is on, the caller is a person, and its re-check passes. Nothing is merged or
 * deployed here or there: the request is queued for the host runner.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";
import { actionsOn, crossOriginRefusal } from "@/lib/runsheet-actions";

export async function POST(request: Request) {
  if (!actionsOn(process.env)) {
    return NextResponse.json({ detail: "Not Found" }, { status: 404 });
  }
  const refusal = crossOriginRefusal(request.headers);
  if (refusal) return NextResponse.json({ detail: refusal }, { status: 403 });
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: "The request body is not JSON." }, { status: 400 });
  }
  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/today/deploy",
      // The backend validates the shape (extra fields forbidden).
      { body: body as never },
    );
    if (!data) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the request." },
        { status: response.status },
      );
    }
    return NextResponse.json(data, { status: response.status });
  } catch {
    return NextResponse.json({ detail: "Could not reach the Mykronos backend." }, { status: 502 });
  }
}
