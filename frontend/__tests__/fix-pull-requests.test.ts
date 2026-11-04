/**
 * A finding names the open dependency-bot pull request that would close it
 * (TheHub #60915): "a pull request that would fix this is open - review it",
 * not a no-fix, accept-risk path. GitHub not answering is said, never shown
 * as "no pull request".
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { FixPullRequests } from "@/components/fix-pull-requests";

const PR = {
  repo_full_name: "acme/payments-api",
  number: 499,
  url: "https://github.com/acme/payments-api/pull/499",
  title: "Bump pypdf from 6.20.1 to 6.21.1 in /backend",
  package: "pypdf",
  to_version: "6.21.1",
};

function render(prs: (typeof PR)[], unread = false): string {
  return renderToStaticMarkup(createElement(FixPullRequests, { prs, unread }));
}

describe("the fix waiting for review", () => {
  it("says a pull request would fix it, and links it", () => {
    const html = render([PR]);

    expect(html).toContain("A pull request that would fix this is open: review it");
    expect(html).toContain('href="https://github.com/acme/payments-api/pull/499"');
    expect(html).toContain("acme/payments-api#499");
    expect(html).toContain("pypdf to 6.21.1");
  });

  it("renders nothing when none is open and GitHub answered", () => {
    expect(render([])).toBe("");
  });

  it("says GitHub was not read rather than implying there is none", () => {
    const html = render([], true);

    expect(html).toMatch(/could not be read/);
  });
});
