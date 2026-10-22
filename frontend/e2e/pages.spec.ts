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

test("product owner is one page: estate, review queue and pull requests as tabs", async ({
  page,
}) => {
  // One nav entry, not Product Owner beside Review queue and Pull requests.
  await page.goto("/");
  const rail = page.getByRole("navigation", { name: "Sections" });
  await expect(rail.getByRole("link", { name: "Product Owner" })).toHaveAttribute(
    "href",
    "/product-owner",
  );
  await expect(rail.getByRole("link", { name: "Review queue" })).toHaveCount(0);
  await expect(rail.getByRole("link", { name: "Pull requests" })).toHaveCount(0);

  // Old bookmarks land on their tab.
  await page.goto("/product-owner/review-queue");
  await expect(page).toHaveURL(/\/product-owner\?tab=review$/);
  await expect(page.getByRole("heading", { name: "Review queue" })).toBeVisible();

  await page.goto("/pull-requests");
  await expect(page).toHaveURL(/\/product-owner\?tab=pull-requests$/);
  await expect(page.getByRole("heading", { name: "Pull requests" })).toBeVisible();
});

test("remediation is one page: the worklist, then the library", async ({ page }) => {
  // One nav entry, not "Remediate today" beside "Remediation library".
  await page.goto("/");
  const rail = page.getByRole("navigation", { name: "Sections" });
  await expect(rail.getByRole("link", { name: "Remediate today" })).toHaveAttribute(
    "href",
    "/remediate",
  );
  await expect(rail.getByRole("link", { name: "Remediation library" })).toHaveCount(0);

  // An old bookmark to the library lands on its section of the merged page.
  await page.goto("/remediation");
  await expect(page).toHaveURL(/\/remediate#library$/);
  await expect(
    page.getByRole("heading", { name: "How to remediate the open findings today" }),
  ).toBeVisible();
  await expect(
    page.locator("#library").getByRole("heading", { name: "Remediation library" }),
  ).toBeVisible();
});
