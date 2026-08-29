/**
 * Proxy for switching one installed workflow on or off (spec 32 §6).
 *
 * Same shape and same reason as the capability-toggle and scan proxies: the
 * admin token stays on this server.
 *
 * `action` is validated here rather than forwarded, because it is a path
 * segment the browser chooses and the two legal values map to two different
 * backend routes. Anything else is a 404 from this route rather than a
 * malformed URL sent onward.
 *
 * Note what this deliberately is *not*: it does not install or uninstall.
 * Adding or removing a workflow file is a pull request the capabilities
 * endpoint opens (spec 03 §3); this only changes whether an already-installed
 * file runs.
 */

import { NextResponse } from "next/server";

import { backendClient } from "@/lib/api";

export async function PUT(
  request: Request,
  context: {
    params: Promise<{ repoId: string; capability: string; action: string }>;
  },
) {
  const { repoId, capability, action } = await context.params;

  if (action !== "enable" && action !== "disable") {
    return NextResponse.json(
      { detail: `Unknown action '${action}'. Expected 'enable' or 'disable'.` },
      { status: 404 },
    );
  }

  const path =
    action === "enable"
      ? ("/api/repos/{repo_id}/workflows/{capability}/enable" as const)
      : ("/api/repos/{repo_id}/workflows/{capability}/disable" as const);

  try {
    const { data, error, response } = await backendClient().PUT(path, {
      params: { path: { repo_id: repoId, capability } },
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
