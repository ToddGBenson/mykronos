/**
 * Proxy for one scan run's archived raw tool output (TheHub #60761). The body
 * is the file itself, not JSON, so this forwards the raw response the way the
 * SBOM proxy does rather than going through `backendClient()`. The admin token
 * is attached here and never reaches the browser; the backend still applies
 * `may_see_raw_output` and serves only files the run lists.
 */

export async function GET(
  _request: Request,
  context: { params: Promise<{ scanRunId: string; filename: string }> },
) {
  const { scanRunId, filename } = await context.params;

  const baseUrl = process.env.MYKRONOS_API_URL ?? "http://127.0.0.1:8100";
  const token = process.env.MYKRONOS_ADMIN_TOKEN ?? "";
  const gate = process.env.MYKRONOS_GATE_TOKEN ?? "";

  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (gate) headers["X-Hub-Token"] = gate;

  try {
    const upstream = await fetch(
      `${baseUrl}/api/dashboard/scan-runs/${encodeURIComponent(scanRunId)}` +
        `/raw/${encodeURIComponent(filename)}`,
      { headers },
    );
    // Streamed through: a scanner's report can run to many megabytes.
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
