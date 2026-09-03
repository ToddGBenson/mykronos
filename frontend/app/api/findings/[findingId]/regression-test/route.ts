/**
 * Proxy for pinning a regression test to a finding (spec 31 §2).
 *
 * Exists for the same reason every other write proxy does: the admin token
 * stays on the server. The client component posts here; this attaches the
 * credential.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ findingId: string }> },
) {
  const { findingId } = await context.params;

  let body: { test_identifier?: string; capability?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: "Body must be JSON." }, { status: 400 });
  }

  const identifier = (body.test_identifier ?? "").trim();
  if (!identifier) {
    return NextResponse.json(
      { detail: "A test identifier is required." },
      { status: 400 },
    );
  }

  // Rejected rather than defaulted. The backend owns which lanes may run a
  // regression test, and a proxy that quietly filled in "unit" would answer
  // for the user and hide a rejection they should see.
  const LANES = ["unit", "functional", "qa"] as const;
  type Lane = (typeof LANES)[number];
  const capability = body.capability as Lane | undefined;
  if (!capability || !LANES.includes(capability)) {
    return NextResponse.json(
      { detail: `A lane is required, one of: ${LANES.join(", ")}.` },
      { status: 400 },
    );
  }

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/findings/{finding_id}/regression-test",
      {
        params: { path: { finding_id: findingId } },
        body: { test_identifier: identifier, capability },
      },
    );

    if (!data) {
      // The backend's own message explains *why* — that the lane is not one
      // that runs tests, say — and rewriting it here would lose that.
      const detail =
        (error as { detail?: string } | undefined)?.detail ??
        `The API rejected the link (HTTP ${response?.status ?? "?"}).`;
      return NextResponse.json({ detail }, { status: response?.status ?? 502 });
    }

    return NextResponse.json(data);
  } catch (cause) {
    return NextResponse.json(
      {
        detail:
          cause instanceof Error && /fetch failed|ECONNREFUSED/i.test(cause.message)
            ? "Cannot reach the Mykronos API."
            : "Unexpected error talking to the Mykronos API.",
      },
      { status: 502 },
    );
  }
}
