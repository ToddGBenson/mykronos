import { defineConfig, devices } from "@playwright/test";

/**
 * Browser end-to-end tests against a running dashboard (`e2e/`).
 *
 * Not the unit tests: vitest runs `__tests__/` in node with no DOM, and the
 * functional suite (`functional/`) speaks HTTP. Neither runs the page's
 * JavaScript, so a page that renders and then does nothing - the static CSP
 * that blocked hydration and left every control inert (see `proxy.ts`) - is
 * green in both. This is the suite that opens the console.
 *
 * Everything comes from the environment, because the stack under test is
 * somebody else's to stand up: `demo-and-dast.yml` points it at the ephemeral
 * demo stack. Defaults are that stack's published port and its public gate
 * literal (`deploy/demo/docker-compose.yml`).
 *
 *   E2E_BASE_URL     the dashboard (default http://127.0.0.1:3200)
 *   DEMO_GATE_TOKEN  the dashboard's MYKRONOS_GATE_TOKEN
 *   E2E_JUNIT        where the JUnit report goes
 *   E2E_OUTPUT_DIR   traces and screenshots of failed tests
 */
export default defineConfig({
  testDir: "./e2e",
  // Each test owns its browser context, so files can run side by side; the
  // stack is read-only from here (nothing in these specs writes).
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // No retries. A flaky browser test that passes on the second go is a
  // finding about the application, and a retry would hide it from the JUnit.
  retries: 0,
  workers: process.env.CI ? 2 : undefined,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  outputDir: process.env.E2E_OUTPUT_DIR ?? "test-results",
  reporter: [
    ["list"],
    ["junit", { outputFile: process.env.E2E_JUNIT ?? "test-results/e2e.xml" }],
  ],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://127.0.0.1:3200",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
