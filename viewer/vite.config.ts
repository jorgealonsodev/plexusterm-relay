import { execSync } from "node:child_process";
import { createHash } from "node:crypto";

import { type Plugin, defineConfig } from "vite";

/** Release hash shown in the footer: VIEWER_BUILD_HASH, else the git commit. */
function buildHash(): string {
  if (process.env.VIEWER_BUILD_HASH) return process.env.VIEWER_BUILD_HASH;
  try {
    return execSync("git rev-parse --short=12 HEAD", { encoding: "utf8" }).trim();
  } catch {
    return "dev";
  }
}

/** Adds Subresource Integrity to every emitted script and stylesheet. */
function subresourceIntegrity(hash: string): Plugin {
  return {
    name: "subresource-integrity",
    apply: "build",
    enforce: "post",
    generateBundle(_, bundle) {
      const html = bundle["index.html"];
      if (!html || html.type !== "asset") return;
      let source = String(html.source);
      for (const file of Object.values(bundle)) {
        const body = file.type === "chunk" ? file.code : file.source;
        const integrity = `sha384-${createHash("sha384").update(body).digest("base64")}`;
        const attr = (tag: string) =>
          new RegExp(`(<${tag}[^>]*(?:src|href)="/${file.fileName.replace(/[.]/g, "\\.")}")`, "g");
        source = source
          .replace(attr("script"), `$1 integrity="${integrity}"`)
          .replace(attr("link"), `$1 integrity="${integrity}"`);
      }
      html.source = source;
      // Served at /build.txt so the share dialog can show the same hash.
      this.emitFile({ type: "asset", fileName: "build.txt", source: `${hash}\n` });
    },
  };
}

const hash = buildHash();

export default defineConfig({
  define: { __BUILD_HASH__: JSON.stringify(hash) },
  plugins: [subresourceIntegrity(hash)],
  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: false,
    // One script and one stylesheet keep the SRI and CSP surface small.
    modulePreload: false,
    cssCodeSplit: false,
  },
});
