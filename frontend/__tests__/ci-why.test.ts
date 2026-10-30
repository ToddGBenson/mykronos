/**
 * The reason printed under a failing job (TheHub #60913).
 */
import { describe, expect, it } from "vitest";

import { failuresWithWhy, whyLines, type CiWhy } from "@/lib/ci-why";
import type { CiJob } from "@/lib/api";

const why = (over: Partial<CiWhy>): CiWhy => ({
  source: "concourse",
  step: null,
  exit_code: null,
  messages: [],
  url: null,
  note: null,
  unavailable: null,
  ...over,
});

describe("whyLines", () => {
  it("names the step, its exit code and the job's own error", () => {
    const lines = whyLines(
      why({
        source: "github",
        step: "demo-and-dast: Run ZAP baseline",
        exit_code: 1,
        messages: ["spider did not reach 100% within 600s"],
        url: "https://github.com/o/r/actions/runs/5/job/77",
      }),
    );

    expect(lines.headline).toBe("Step demo-and-dast: Run ZAP baseline exited 1");
    expect(lines.messages).toEqual(["spider did not reach 100% within 600s"]);
    expect(lines.source).toBe("GitHub Actions");
    expect(lines.url).toContain("/job/77");
  });

  it("says failed, not exited, when no exit code is known", () => {
    expect(whyLines(why({ step: "upload" })).headline).toBe("Step upload failed");
  });

  it("an exit code of zero is still printed", () => {
    expect(whyLines(why({ step: "scan", exit_code: 0 })).headline).toBe("Step scan exited 0");
  });

  it("degrades to reason unavailable with the reason", () => {
    const lines = whyLines(
      why({ unavailable: "Concourse did not return this build's events", messages: ["x"] }),
    );

    expect(lines.headline).toBe("reason unavailable: Concourse did not return this build's events");
    expect(lines.messages).toEqual([]);
  });

  it("keeps the note and caps the messages at three", () => {
    const lines = whyLines(why({ messages: ["a", "b", "c", "d"], note: "no ::error line" }));

    expect(lines.messages).toEqual(["a", "b", "c"]);
    expect(lines.note).toBe("no ::error line");
  });
});

describe("failuresWithWhy", () => {
  it("keeps only failed jobs that carry a reason", () => {
    const jobs = [
      { name: "unit", status: "succeeded", why: null },
      { name: "sast", status: "failed", why: why({ step: "scan" }) },
      { name: "iac", status: "failed", why: null },
    ] as CiJob[];

    expect(failuresWithWhy(jobs).map((j) => j.name)).toEqual(["sast"]);
  });
});
