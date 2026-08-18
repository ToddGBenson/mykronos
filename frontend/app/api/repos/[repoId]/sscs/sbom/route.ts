/**
 * Proxy for the SBOM download (spec 18 §8.2). Unlike every other proxy in
 * this app, the backend response here is not JSON — it's the archived file
 * itself — so this bypasses `backendClient()` (which assumes a JSON body per
 * the OpenAPI schema) and forwards the raw response instead. The admin token
 * still never reaches the browser: attached here, from the same server-only
 * environment variable every other proxy route reads.
 */

export async function GET(
  request: Request,
  context: { params: Promise<{ repoId: string }> },
) {
  const { repoId } = await context.params;
  const evidenceId = new URL(request.url).searchParams.get("evidence_id");
  if (!evidenceId) {
    return Response.json({ detail: "evidence_id is required." }, { status: 422 });
  }

  const baseUrl = process.env.MYKRONOS_API_URL ?? "http://127.0.0.1:8100";
  const token = process.env.MYKRONOS_ADMIN_TOKEN ?? "";
  const gate = process.env.MYKRONOS_GATE_TOKEN ?? "";

  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (gate) headers["X-Hub-Token"] = gate;

  try {
    const upstream = await fetch(
      `${baseUrl}/api/dashboard/repos/${encodeURIComponent(repoId)}/sscs/sbom` +
        `?evidence_id=${encodeURIComponent(evidenceId)}`,
      { headers },
    );
    // Streamed through, not buffered: an SBOM for a large dependency graph
    // can be a multi-megabyte JSON document, and there is no reason to hold
    // the whole thing in this server's memory just to relay it.
    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        "Content-Type": upstream.headers.get("Content-Type") ?? "application/octet-stream",
        "Content-Disposition": upstream.headers.get("Content-Disposition") ?? "attachment",
      },
    });
  } catch {
    return Response.json(
      { detail: "Could not reach the Mykronos backend." },
      { status: 502 },
    );
  }
}
