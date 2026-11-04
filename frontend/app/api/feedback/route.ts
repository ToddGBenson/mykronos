/**
 * Proxy for dashboard feedback (TheHub #61132). The admin token is attached
 * on this server; the backend files the TheHub story with the Hub token it
 * holds. The browser sees neither, and nothing here can reach GitHub. The
 * backend's 503 ("feedback is unavailable") is passed through, not reworded
 * and not routed anywhere else.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

const UNREACHABLE = { detail: "Could not reach the Mykronos backend." };

export async function GET() {
  try {
    const { data, error, response } = await backendClient().GET("/api/feedback");
    if (!data) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the request." },
        { status: response.status },
      );
    }
    return NextResponse.json(data);
  } catch {
    return NextResponse.json(UNREACHABLE, { status: 502 });
  }
}

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: "The report was not JSON." }, { status: 400 });
  }

  try {
    const { data, error, response } = await backendClient().POST("/api/feedback", {
      body: body as never,
    });
    if (!data) {
      return NextResponse.json(
        (error as object) ?? { detail: "The backend refused the report." },
        { status: response.status },
      );
    }
    return NextResponse.json(data, { status: 201 });
  } catch {
    return NextResponse.json(UNREACHABLE, { status: 502 });
  }
}
