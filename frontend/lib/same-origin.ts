/**
 * Why a browser request may not reach a write proxy, or null (TheHub #61142;
 * shared by the raise and feedback proxies from #61379).
 *
 * The gate's cookie is SameSite=Lax, which stops a cross-site form but not a
 * page on a sibling subdomain of the same site. So the action routes take only
 * JSON (a cross-origin JSON POST needs a CORS preflight nobody answers), and
 * refuse a request the browser marks as not same-origin, or whose Origin is
 * another host.
 */
export function crossOriginRefusal(headers: Headers): string | null {
  const type = headers.get("content-type") ?? "";
  if (!type.toLowerCase().startsWith("application/json")) return "Send JSON.";
  const site = headers.get("sec-fetch-site");
  if (site && site !== "same-origin") return "Cross-origin requests are refused.";
  const origin = headers.get("origin");
  const host = headers.get("x-forwarded-host") ?? headers.get("host");
  if (origin) {
    let originHost = "";
    try {
      originHost = new URL(origin).host;
    } catch {
      return "Cross-origin requests are refused.";
    }
    if (!host || originHost !== host) return "Cross-origin requests are refused.";
  }
  return null;
}
