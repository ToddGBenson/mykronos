import { test, expect } from "@playwright/test";

import { GATE_TOKEN } from "./fixtures";

/**
 * The perimeter gate (`proxy.ts`, `lib/gate.ts`), as a browser meets it.
 *
 * `__tests__/proxy.test.ts` proves the decision on a constructed request.
 * This proves the part only a browser can: that the link a person is sent
 * leaves a cookie the browser actually keeps and sends back, and that the
 * token is gone from the address bar afterwards.
 *
 * Plain `@playwright/test`, not the signed-in fixture: these tests start with
 * no cookie, and a 401 is the console error they expect to see.
 */

test("with no token the dashboard answers 401 and shows nothing", async ({ page }) => {
  const response = await page.goto("/");

  expect(response?.status()).toBe(401);
  expect(response?.headers()["www-authenticate"]).toContain("X-Hub-Token");
  await expect(page.locator("body")).toContainText("Not authorised for this host.");
  // Nothing of the application rendered: no layout, no navigation.
  await expect(page.getByRole("group", { name: "Colour theme" })).toHaveCount(0);
});

test("a wrong token is refused the same way", async ({ page }) => {
  const response = await page.goto("/?_token=not-the-token");

  expect(response?.status()).toBe(401);
  expect(page.url()).toContain("_token=");
  expect(await page.context().cookies()).toEqual([]);
});

test("a ?_token= link sets the cookie, drops the token from the URL and renders", async ({
  page,
}) => {
  const response = await page.goto(`/triage?_token=${encodeURIComponent(GATE_TOKEN)}&keep=1`);

  // One redirect, from the gate.
  const redirect = response?.request().redirectedFrom();
  expect(redirect, "the link was not redirected").toBeTruthy();
  expect((await redirect!.response())?.status()).toBe(302);

  // The token is out of the address bar; every other parameter survived.
  const landed = new URL(page.url());
  expect(landed.pathname).toBe("/triage");
  expect(landed.searchParams.has("_token")).toBe(false);
  expect(landed.searchParams.get("keep")).toBe("1");
  expect(response?.status()).toBe(200);

  // The browser kept the cookie, and nothing in the page can read it.
  const cookie = (await page.context().cookies()).find((c) => c.name === "hub_token");
  expect(cookie, "no hub_token cookie was stored").toBeTruthy();
  expect(cookie!.value).toBe(GATE_TOKEN);
  expect(cookie!.httpOnly).toBe(true);
  expect(cookie!.sameSite).toBe("Lax");
  expect(await page.evaluate(() => document.cookie)).not.toContain("hub_token");

  // The application rendered, and a second visit needs no token at all.
  await expect(page.getByRole("group", { name: "Colour theme" })).toBeVisible();
  const again = await page.goto("/");
  expect(again?.status()).toBe(200);
});
