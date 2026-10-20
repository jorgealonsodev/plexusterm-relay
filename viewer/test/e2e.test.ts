// TypeScript viewer ⇄ real Rust relay ⇄ Rust demo sharer running `cat` in a PTY.
// Needs `cargo build --bins` first; skipped when the binaries are missing.

import { type ChildProcess, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { type ClientEvent, ShareClient } from "../src/client";
import { fromB64, utf8 } from "../src/protocol/bytes";

const bin = (name: string) => fileURLToPath(new URL(`../../target/debug/${name}`, import.meta.url));
const RELAY = bin("plexusterm-relay");
const DEMO = bin("plexusterm-share-demo");
const haveBinaries = existsSync(RELAY) && existsSync(DEMO);
const TOKEN = "viewer-e2e-token-0123456789";
const port = 20000 + Math.floor(Math.random() * 20000);
const relayUrl = `ws://127.0.0.1:${port}`;

let relay: ChildProcess;
let demo: ChildProcess;
let link: string;

async function until(check: () => boolean, what: string, ms = 5000): Promise<void> {
  const start = Date.now();
  while (!check()) {
    if (Date.now() - start > ms) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

describe.skipIf(!haveBinaries)("web viewer against the Rust relay and sharer", () => {
  beforeAll(async () => {
    relay = spawn(RELAY, [], {
      env: { ...process.env, RELAY_TOKENS: TOKEN, RELAY_LISTEN: `127.0.0.1:${port}` },
      stdio: "ignore",
    });
    await new Promise((r) => setTimeout(r, 300));
    demo = spawn(
      DEMO,
      ["--relay", relayUrl, "--viewer-origin", "http://view.test", "--access", "type", "--approve", "auto",
        "--size", "80x24", "--", "sh", "-c", "printf READY; exec cat"],
      { env: { ...process.env, PLEXUSTERM_RELAY_TOKEN: TOKEN }, stdio: ["ignore", "pipe", "ignore"] },
    );
    let out = "";
    demo.stdout!.on("data", (d) => (out += d));
    await until(() => /can type: (\S+)/.test(out), "share link");
    link = /can type: (\S+)/.exec(out)![1]!;
  });

  afterAll(() => {
    demo?.kill();
    relay?.kill();
  });

  it("joins, sees output, types, and resumes after a dropped connection", async () => {
    const [, id, secret] = /\/s\/([^#]+)#(.+)$/.exec(link)!;
    const events: ClientEvent[] = [];
    let screen = "";
    let resets = 0;
    const client = new ShareClient({
      relayUrl,
      shareId: fromB64(id!, 16)!,
      secret: fromB64(secret!, 32)!,
      onEvent: (e) => {
        events.push(e);
        if (e.t === "reset") {
          screen = "";
          resets++;
        }
        if (e.t === "write") screen += new TextDecoder().decode(e.data);
      },
    });
    await client.start();
    await until(() => screen.includes("READY"), "snapshot with READY");
    expect(events.find((e) => e.t === "joined")).toEqual({ t: "joined", access: "type", cols: 80, rows: 24 });

    await until(() => client.canType, "typing allowed");
    client.input(utf8("hello\r"));
    await until(() => (screen.match(/hello/g) ?? []).length >= 2, "echo and cat output");

    // Drop the connection: the client reconnects with a fresh handshake and
    // resumes from its last output number without a new snapshot.
    (client as unknown as { ws: WebSocket }).ws.close();
    await until(() => events.some((e) => e.t === "reconnecting"), "reconnecting");
    await until(() => events.filter((e) => e.t === "joined").length === 2, "rejoined", 8000);
    await until(() => client.canType, "typing allowed again");
    client.input(utf8("again\r"));
    await until(() => (screen.match(/again/g) ?? []).length >= 2, "output after reconnect");
    expect(resets).toBe(1);
    client.stop();
  }, 20000);
});
