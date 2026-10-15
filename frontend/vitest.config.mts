import { defineConfig } from "vitest/config";

// The proxy runs on the Next server, so its tests run in node: no DOM, and
// `next/server`'s NextRequest and NextResponse are the real ones.
export default defineConfig({
  test: {
    environment: "node",
    include: ["__tests__/**/*.test.ts"],
  },
});
