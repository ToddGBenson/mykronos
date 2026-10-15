import { test as base, expect, type Page } from "@playwright/test";

/**
 * The demo stack's perimeter-gate token. Public by design: every demo token is
 * a literal in `deploy/demo/docker-compose.yml`, valid only on a stack that
 * holds seeded data and is destroyed after the run.
 */
export const GATE_TOKEN = process.env.DEMO_GATE_TOKEN ?? "demo-gate-token-not-a-secret";

/** The repositories `deploy/demo/seed.py` onboards. */
export const SEEDED_REPOS = [
  "acme/checkout-api",
  "acme/customer-portal",
  "acme/payments-worker",
  "acme/internal-tools",
] as const;

/** What went wrong in the browser while a test ran. */
export interface BrowserProblems {
  /** `securitypolicyviolation` events, as `directive blocked-uri`. */
  csp: string[];
  /** `console.error` messages, CSP reports among them. */
  console: string[];
  /** Uncaught exceptions - React's #418/#412 hydration errors land here. */
  pageErrors: string[];
}

/**
 * Reports every CSP violation the page itself observes, as it happens.
 *
 * Listening in the page rather than only on the console: the event carries
 * the directive that refused, and it fires for a blocked inline script however
 * Chromium words its console message. Installed before any page script runs,
 * so a violation during hydration is counted, and reported through a binding
 * that survives navigation, so a violation on the first page of a test is not
 * lost when it moves to the second.
 */
export async function recordCspViolations(page: Page, sink: string[]): Promise<void> {
  await page.exposeFunction("__reportCspViolation", (entry: string) => sink.push(entry));
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) => {
      const report = (window as unknown as { __reportCspViolation: (e: string) => void })
        .__reportCspViolation;
      void report(`${event.violatedDirective} ${event.blockedURI}`);
    });
  });
}

/**
 * A signed-in browser that fails the test on anything the console shows.
 *
 * The cookie is the one the gate sets after a `?_token=` link (`proxy.ts`),
 * added directly so each test starts on the page it is about; `gate.spec.ts`
 * walks the link itself. `problems` is checked after every test, so a page
 * that renders and then throws, or whose scripts the CSP refused, is red even
 * when every visible assertion passed - which is the failure this suite
 * exists to see.
 */
export const test = base.extend<{ problems: BrowserProblems }>({
  problems: [
    async ({ page, context, baseURL }, use) => {
      await context.addCookies([
        { name: "hub_token", value: GATE_TOKEN, url: baseURL ?? "http://127.0.0.1:3200" },
      ]);
      const problems: BrowserProblems = { csp: [], console: [], pageErrors: [] };
      await recordCspViolations(page, problems.csp);
      page.on("console", (message) => {
        if (message.type() === "error") problems.console.push(message.text());
      });
      page.on("pageerror", (error) => problems.pageErrors.push(error.message));

      await use(problems);

      expect.soft(problems.csp, "CSP violations").toEqual([]);
      expect.soft(problems.pageErrors, "uncaught page errors").toEqual([]);
      expect(problems.console, "console errors").toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };
