/**
 * Proxy for the Ctrl+K jump box's search (TheHub #60976). The admin token is
 * attached on this server and never reaches the browser; the backend applies
 * the two-character floor and the fifty-result cap, and its 400 is passed
 * through rather than reworded.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function GET(request: Request) {
  const params = new URL(request.url).searchParams;
  const q = params.get("q") ?? "";
  const limit = Number.parseInt(params.get("limit") ?? "20", 10);

  try {
    const { data, error, response } = await backendClient().GET("/api/dashboard/search", {
      params: { query: { q, limit: Number.isFinite(limit) && limit > 0 ? limit : 20 } },
    });

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
