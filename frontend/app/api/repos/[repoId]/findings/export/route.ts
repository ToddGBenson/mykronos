/**
 * Proxy for the findings exports (TheHub #60762): CSV, SARIF or a printable
 * HTML report. The body is a file, not JSON, so this forwards the raw response
 * the way the SBOM proxy does. The admin token is attached here and never
 * reaches the browser; no export carries raw tool output, whoever asks.
 */

const PASSED_THROUGH = [
  "Content-Type",
  "Content-Disposition",
  "Content-Security-Policy",
  "X-Mykronos-Truncated",
];

export async function GET(
  request: Request,
  context: { params: Promise<{ repoId: string }> },
) {
  const { repoId } = await context.params;
  const query = new URL(request.url).searchParams.toString();

  const baseUrl = process.env.MYKRONOS_API_URL ?? "http://127.0.0.1:8100";
  const token = process.env.MYKRONOS_ADMIN_TOKEN ?? "";
  const gate = process.env.MYKRONOS_GATE_TOKEN ?? "";

  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (gate) headers["X-Hub-Token"] = gate;

  try {
    const upstream = await fetch(
      `${baseUrl}/api/dashboard/repos/${encodeURIComponent(repoId)}/findings/export` +
        (query ? `?${query}` : ""),
      { headers },
    );
    const forwarded: Record<string, string> = {};
    for (const name of PASSED_THROUGH) {
      const value = upstream.headers.get(name);
      if (value) forwarded[name] = value;
    }
    return new Response(upstream.body, { status: upstream.status, headers: forwarded });
  } catch {
    return Response.json(
      { detail: "Could not reach the Mykronos backend." },
      { status: 502 },
    );
  }
}
