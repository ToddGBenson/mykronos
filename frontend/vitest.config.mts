import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

// The proxy runs on the Next server, so its tests run in node: no DOM, and
// `next/server`'s NextRequest and NextResponse are the real ones.
export default defineConfig({
  // The app's own `@/` alias (tsconfig `paths`), so a test can import a route
  // module as Next would resolve it.
  resolve: {
    alias: { "@": fileURLToPath(new URL(".", import.meta.url)) },
  },
  test: {
    environment: "node",
    include: ["__tests__/**/*.test.ts"],
  },
});
