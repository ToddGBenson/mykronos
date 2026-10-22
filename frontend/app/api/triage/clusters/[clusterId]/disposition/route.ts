/**
 * Proxy for one disposition covering a whole cluster (TheHub #60887).
 * Same shape and same reason as every other proxy here: the admin token stays
 * on this server.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function POST(
  request: Request,
  context: { params: Promise<{ clusterId: string }> },
) {
  const { clusterId } = await context.params;

  let body: { status?: string; reason?: string; member_ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: "Body must be JSON." }, { status: 400 });
  }
  if (!body.status) {
    return NextResponse.json({ detail: "A status is required." }, { status: 400 });
  }

  try {
    const { data, error, response } = await backendClient().POST(
      "/api/dashboard/triage/clusters/{cluster_id}/disposition",
      {
        params: { path: { cluster_id: clusterId } },
        body: {
          status: body.status as never,
          reason: body.reason ?? "",
          // Acceptances need a review date and a reason code each, which this
          // page does not collect; the backend's own default, stated.
          indefinite: false,
          // Forwarded as given: the backend refuses when the cluster changed
          // since the person looked, and a proxy that dropped this would let a
          // decision cover members nobody saw.
          ...(Array.isArray(body.member_ids) ? { member_ids: body.member_ids } : {}),
        },
      },
    );
    if (!data) {
      const detail =
        (error as { detail?: string } | undefined)?.detail ??
        `The API rejected the disposition (HTTP ${response?.status ?? "?"}).`;
      return NextResponse.json({ detail }, { status: response?.status ?? 502 });
    }
    return NextResponse.json(data);
  } catch {
    return NextResponse.json(
      { detail: "Could not reach the Mykronos backend." },
      { status: 502 },
    );
  }
}
