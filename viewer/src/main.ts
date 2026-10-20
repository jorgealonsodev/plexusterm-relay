// Viewer page: one click to join, then the shared terminal (PRD-share §4.2).

import "@xterm/xterm/css/xterm.css";
import "./style.css";

import { Terminal } from "@xterm/xterm";

import { type ClientEvent, ShareClient } from "./client";
import type { ErrorCode } from "./engine";
import { fromB64, utf8 } from "./protocol/bytes";
import { deepLink } from "./protocol/link";
import { strings } from "./strings";

declare const __BUILD_HASH__: string;

const t = strings();
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const gate = $("gate");
const gateText = $("gate-text");
const joinButton = $<HTMLButtonElement>("join");
const openAppButton = $<HTMLButtonElement>("open-app");
const wrap = $("terminal-wrap");
const status = $("status");
const accessLabel = $("access");
const expiryLabel = $("expiry");

document.documentElement.lang = t === strings(["es"]) ? "es" : "en";
$("build").textContent = __BUILD_HASH__;
$("trust").textContent = t.trust;

// Read the key, then drop it from the address bar and history at once.
const pathMatch = /^\/s\/([A-Za-z0-9_-]+)\/?$/.exec(location.pathname);
const fragment = location.hash.slice(1);
history.replaceState(null, "", location.pathname);

function relayUrl(): string {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="plexusterm-relay"]')?.content ?? "";
  if (meta && meta !== "__RELAY_URL__") return meta;
  // Development fallback: relay on port 8080 of the page's host.
  return `${location.protocol === "https:" ? "wss" : "ws"}://${location.hostname}:8080`;
}

function supported(): boolean {
  return (
    typeof crypto !== "undefined" &&
    !!crypto.subtle &&
    typeof WebSocket !== "undefined" &&
    typeof DecompressionStream !== "undefined"
  );
}

function showGate(text: string, withButton = false): void {
  gate.hidden = false;
  gateText.textContent = text;
  joinButton.hidden = !withButton;
  openAppButton.hidden = !withButton || !appLink;
}

/** The share as a `plexusterm://` link, built here so the key never
 * leaves the fragment; `null` when the relay is not `wss://`. */
let appLink: string | null = null;

function say(text: string | null): void {
  status.hidden = !text;
  status.textContent = text ?? "";
}

const refusal: Record<ErrorCode, string> = {
  not_found: t.notFound,
  bad_key: t.badKey,
  full: t.full,
  rate_limited: t.rateLimited,
  version: t.outdated,
  too_large: t.ended,
  unauthorized: t.notFound,
  conflict: t.notFound,
  too_many_shares: t.notFound,
  bad_request: t.outdated,
};

function start(shareId: Uint8Array<ArrayBuffer>, secret: Uint8Array<ArrayBuffer>): void {
  const relay = relayUrl();
  let term: Terminal | null = null;

  const finish = (text: string) => {
    // Clear the terminal buffer on the way out (PRD §6.2).
    term?.dispose();
    term = null;
    wrap.hidden = true;
    accessLabel.hidden = true;
    say(null);
    showGate(text);
  };

  const setAccess = (access: "view" | "type") => {
    accessLabel.hidden = false;
    accessLabel.textContent = access === "type" ? `⌨ ${t.canType}` : `👁 ${t.viewOnly}`;
    accessLabel.dataset.access = access;
    if (term) term.options.disableStdin = access !== "type";
  };

  const client = new ShareClient({
    relayUrl: relay,
    shareId,
    secret,
    onEvent: (e: ClientEvent) => {
      switch (e.t) {
        case "connecting":
          break;
        case "waiting":
          showGate(t.waiting);
          break;
        case "joined":
          gate.hidden = true;
          wrap.hidden = false;
          say(null);
          if (!term) {
            term = new Terminal({
              cols: e.cols,
              rows: e.rows,
              screenReaderMode: true,
              convertEol: false,
              scrollback: 10_000,
              fontSize: 14,
            });
            term.open($("terminal"));
            term.onData((d) => client.input(utf8(d)));
          } else {
            term.resize(e.cols, e.rows);
          }
          setAccess(e.access);
          break;
        case "reset":
          term?.reset();
          break;
        case "write":
          term?.write(e.data);
          break;
        case "resized":
          term?.resize(e.cols, e.rows);
          break;
        case "access":
          setAccess(e.access);
          if (e.access === "view") say(t.nowViewOnly);
          break;
        case "input_paused":
          say(e.paused ? t.inputPaused : null);
          break;
        case "program_exited":
          say(t.programExited);
          break;
        case "sharer_away":
          say(t.sharerAway);
          break;
        case "sharer_back":
          say(null);
          break;
        case "reconnecting":
          say(t.reconnecting);
          break;
        case "unreachable":
          showGate(t.unreachable(new URL(relay).host));
          break;
        case "expiry": {
          const time = new Date(e.expiresAt * 1000).toLocaleTimeString(undefined, {
            hour: "2-digit",
            minute: "2-digit",
          });
          expiryLabel.hidden = false;
          expiryLabel.textContent = t.endsAt(time);
          break;
        }
        case "denied":
          finish(t.denied);
          break;
        case "kicked":
          finish(t.ended);
          break;
        case "ended":
          finish(e.reason === "offline" ? t.offline : t.ended);
          break;
        case "refused":
          finish(refusal[e.code] ?? t.notFound);
          break;
        case "dropped":
          break;
      }
    },
  });
  addEventListener("pagehide", () => client.stop());
  void client.start();
}

(function main() {
  if (!supported()) return showGate(t.unsupported);
  const shareId = pathMatch ? fromB64(pathMatch[1]!, 16) : null;
  if (!shareId) return showGate(t.notFound);
  const secret = fromB64(fragment, 32);
  if (!secret) return showGate(t.incomplete);
  joinButton.textContent = t.join;
  openAppButton.textContent = t.openInApp;
  appLink = deepLink(relayUrl(), pathMatch![1]!, fragment);
  showGate(t.joinPrompt, true);
  openAppButton.addEventListener("click", () => {
    if (appLink) location.assign(appLink);
  });
  // One click before connecting, so link-preview bots never join.
  joinButton.addEventListener(
    "click",
    () => {
      showGate(t.waiting);
      start(shareId, secret);
    },
    { once: true },
  );
})();
