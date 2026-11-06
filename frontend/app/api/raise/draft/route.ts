/** Proxy for the pre-filled draft of a raise (TheHub #60911). */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const kind = url.searchParams.get("kind") as "lane" | "finding" | "health" | null;
  const subject = url.searchParams.get("subject");
  if (!kind || !subject) {
    return NextResponse.json({ detail: "kind and subject are required." }, { status: 400 });
  }
  try {
    const { data, error, response } = await backendClient().GET("/api/dashboard/raise/draft", {
      params: { query: { kind, subject } },
      cache: "no-store",
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
