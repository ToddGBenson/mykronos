import { test, expect } from "./fixtures";

/**
 * The page hydrates under the CSP, and its controls answer.
 *
 * The defect this exists for is in `proxy.ts`'s history: a static
 * `script-src 'self'` blocked the App Router's inline scripts, React threw,
 * and every client component on the site rendered and did nothing. The header
 * was verified as *present* and never as *harmless*. An HTTP test cannot see
 * the difference; a browser can, in the console and in a click that does
 * nothing.
 *
 * The fixture fails any test here on a CSP violation, an uncaught error or a
 * console error, so each page below is checked for all three by loading it.
 */

const PAGES = ["/", "/triage", "/trends", "/decisions", "/product-owner"];

for (const path of PAGES) {
  test(`${path} is served with a nonce CSP and loads without a violation`, async ({
    page,
    problems,
  }) => {
    const response = await page.goto(path);

    expect(response?.status()).toBe(200);
    // Under the real policy: a nonce, and no 'unsafe-inline' for scripts.
    const csp = response?.headers()["content-security-policy"] ?? "";
    expect(csp).toMatch(/script-src [^;]*'nonce-/);
    expect(csp).not.toMatch(/script-src [^;]*'unsafe-inline'/);

    await page.waitForLoadState("networkidle");
    expect(problems.csp).toEqual([]);
    expect(problems.pageErrors).toEqual([]);
  });
}

test("the theme toggle responds to a click", async ({ page }) => {
  // In the layout, so on every page, and entirely client-side: if hydration
  // failed this button renders and the click changes nothing.
  await page.goto("/");
  const group = page.getByRole("group", { name: "Colour theme" });
  const dark = group.getByRole("button", { name: "dark" });
  const light = group.getByRole("button", { name: "light" });

  await dark.click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(dark).toHaveAttribute("aria-pressed", "true");

  await light.click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(light).toHaveAttribute("aria-pressed", "true");
  await expect(dark).toHaveAttribute("aria-pressed", "false");
});

test("a filter dropdown navigates when a value is chosen", async ({ page }) => {
  // `FilterSelect` pushes a new query string through the client router. A
  // dropdown that is not hydrated changes its own value and nothing else.
  await page.goto("/triage");
  const severity = page.getByRole("combobox", { name: "Severity" });

  await severity.selectOption("critical");

  await expect(page).toHaveURL(/[?&]severity=critical(&|$)/);
  await expect(severity).toHaveValue("critical");
  await expect(page.getByRole("heading", { name: "Triage queue" })).toBeVisible();
});
