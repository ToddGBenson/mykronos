/**
 * The page the perimeter gate shows a browser it refuses (TheHub #61143, P9).
 *
 * The refusal used to be `{"detail": "Not authorised for this host."}` for
 * everyone, which is right for a script and useless for a person: it does
 * not say that the dashboard is opened through an access link, or that a
 * link stops working when the token is rotated.
 *
 * Static on purpose. It is the same bytes for an absent, wrong or malformed
 * token, so it tells a guesser nothing the JSON did not, and it never echoes
 * what was presented. It runs no script, loads nothing and cannot be framed:
 * its CSP is `default-src 'none'` with only its own inline style allowed.
 */

export const GATE_PAGE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; " +
  "form-action 'none'; frame-ancestors 'none'";

export const GATE_PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Access link needed · MyKronos</title>
<style>
  :root { --bg: #f3f5f8; --surf: #ffffff; --rule: #d5dbe3; --ink: #131821; --ink2: #3a4352; --accent: #0b6e80; color-scheme: light dark; }
  @media (prefers-color-scheme: dark) { :root { --bg: #0d1117; --surf: #161b23; --rule: #2b3442; --ink: #e2e8f0; --ink2: #b4bfcd; --accent: #3fc1d4; } }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--ink);
    font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; padding: 16px; box-sizing: border-box; }
  main { max-width: 34rem; background: var(--surf); border: 1px solid var(--rule); border-left: 4px solid var(--accent); padding: 20px 24px; }
  .eyebrow { font: 600 12px/1 ui-monospace, "Cascadia Code", Menlo, monospace; letter-spacing: .14em; color: var(--ink2); }
  h1 { font-size: 1.375rem; line-height: 1.25; margin: 10px 0 8px; }
  p, li { color: var(--ink2); margin: 0 0 8px; }
  ol { padding-left: 1.25rem; margin: 0 0 8px; }
</style>
</head>
<body>
<main>
<p class="eyebrow">MYKRONOS · 401</p>
<h1>This dashboard opens through its access link</h1>
<p>Not authorised for this host. This browser has not presented a valid access link, so nothing here was shown.</p>
<ol>
<li>Open the dashboard from the link the operator's Start-Here script prints. Following it once keeps you signed in for a day.</li>
<li>If a link that used to work stopped, the token has been rotated: ask the operator for a fresh link.</li>
</ol>
<p>Scripts and API clients send the token in the X-Hub-Token header instead.</p>
</main>
</body>
</html>
`;
