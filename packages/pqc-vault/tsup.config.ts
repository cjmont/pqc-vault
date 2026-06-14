import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  outExtension({ format }) {
    return { js: format === "esm" ? ".mjs" : ".cjs" };
  },
  dts: true,
  clean: true,
  sourcemap: true,
  // The native loader is shipped beside dist/ and required at runtime; never
  // bundle it (its relative require of the .node must stay intact).
  external: ["../binding.js"],
});
