/**
 * The Agents page is reachable (TheHub #61144, screenshot pass): it sits
 * beside MyKronos Health, so it lands under Platform once the nav is grouped
 * by job (#1060) and at the end of the one group before that.
 */
import { describe, expect, it } from "vitest";

import { NAV } from "../lib/nav";

describe("the nav links to /agents", () => {
  it("lists Agents directly after MyKronos Health, in the same group", () => {
    const group = NAV.find((g) => g.items.some((i) => i.href === "/agents"));
    expect(group).toBeDefined();
    const labels = group!.items.map((i) => i.label);
    expect(labels[labels.indexOf("Agents") - 1]).toBe("MyKronos Health");
    expect(group!.items).toContainEqual({ label: "Agents", href: "/agents" });
  });
});
