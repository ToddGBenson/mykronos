/**
 * Proxy for raising a Hub incident or story (TheHub #60911). This server
 * holds the credential; the browser never does. The backend builds the
 * evidence and audits who raised it.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";
import { crossOriginRefusal } from "@/lib/same-origin";

export async function POST(request: Request) {
  const refusal = crossOriginRefusal(request.headers);
  if (refusal) return NextResponse.json({ detail: refusal }, { status: 403 });
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: "The request body is not JSON." }, { status: 400 });
  }
  try {
    const { data, error, response } = await backendClient().POST("/api/dashboard/raise", {
      body: body as never,
    });
    if (!data) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the request." },
        { status: response.status },
      );
    }
    // 201 for a new item, 200 when this subject was already raised and is still open.
    return NextResponse.json(data, { status: response.status === 200 ? 200 : 201 });
  } catch {
    return NextResponse.json({ detail: "Could not reach the Mykronos backend." }, { status: 502 });
  }
}
