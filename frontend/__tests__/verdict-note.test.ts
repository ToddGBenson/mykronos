/**
 * The verdict badge carries the read-coverage note (TheHub #60962), run rather
 * than read: rendered to markup, so a prop that is accepted and never drawn
 * fails here.
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { Verdict } from "../components/primitives";

function render(props: Parameters<typeof Verdict>[0]): string {
  return renderToStaticMarkup(createElement(Verdict, props));
}

describe("Verdict", () => {
  it("shows the note beside the verdict", () => {
    const html = render({ recommendation: "go", score: 4, note: "go - read 31% of the code" });
    expect(html).toContain("go - read 31% of the code");
    expect(html).toContain(">go<");
  });

  it("shows an unknown read share rather than nothing", () => {
    expect(render({ recommendation: "go", note: "go - read coverage unknown" })).toContain(
      "read coverage unknown",
    );
  });

  it("draws no note when there is none", () => {
    expect(render({ recommendation: "go", score: 4 })).not.toContain("read ");
  });
});
