import { test, expect, SEEDED_REPOS } from "./fixtures";

/**
 * The core pages, rendered from the seeded demo backend.
 *
 * The functional suite already asserts these answer 200 with the repository
 * names in the HTML. What it cannot assert is what a person sees after the
 * scripts ran: an error panel swapped in on the client, a link that does not
 * navigate, a console full of errors behind a page that looks fine. Every test
 * here also fails on any console error (see `fixtures.ts`).
 */

test("the portfolio lists every seeded repository", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Portfolio" })).toBeVisible();
  for (const name of SEEDED_REPOS) {
    await expect(page.getByRole("link", { name, exact: true })).toBeVisible();
  }
  await expect(page.getByText("Open critical")).toBeVisible();
});

test("a repository opens from the portfolio and shows its findings", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: "acme/checkout-api", exact: true }).click();

  await expect(page).toHaveURL(/\/repos\/[^/?]+/);
  await expect(page.getByRole("heading", { name: "acme/checkout-api" })).toBeVisible();

  // The findings tab, then narrowed to critical through its own dropdown:
  // the seed gives checkout-api a critical SAST finding (CWE-89).
  const repoUrl = new URL(page.url());
  await page.goto(`${repoUrl.pathname}?tab=findings`);
  const severity = page.getByRole("combobox", { name: "Severity" });
  await expect(severity).toBeVisible();
  await severity.selectOption("critical");

  await expect(page).toHaveURL(/[?&]severity=critical(&|$)/);
  await expect(page.getByText("SQL injection in order lookup").first()).toBeVisible();
});

test("the triage queue renders the estate's findings", async ({ page }) => {
  await page.goto("/triage");

  await expect(page.getByRole("heading", { name: "Triage queue" })).toBeVisible();
  await expect(page.getByText("SQL injection in order lookup").first()).toBeVisible();
});

test("the product-owner console lists every seeded repository", async ({ page }) => {
  await page.goto("/product-owner");

  await expect(page.getByRole("heading", { name: "Product Owner · estate" })).toBeVisible();
  for (const name of SEEDED_REPOS) {
    await expect(page.getByRole("link", { name, exact: true })).toBeVisible();
  }
});
