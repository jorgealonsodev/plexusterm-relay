// Viewer engine: mirrors crates/client/src/viewer.rs. No IO: the client
// feeds relay messages in and executes the returned actions in order.

import { type Bytes, concat, copy, fromB64, toB64, utf8 } from "./protocol/bytes";
import { type Access, type Content, decode, encode } from "./protocol/content";
import { DIR_TO_SHARER, DIR_TO_VIEWER, Opener, Sealer } from "./protocol/frame";
import { type LinkKeys, ROLE_VIEWER, deriveKeys, prove } from "./protocol/keys";
import { ViewerHandshake } from "./protocol/noise";

export const PROTOCOL_VERSION = 1;
const CHUNK_INFLATED_MAX = 4 * 24 * 1024;

export type EndReason = "stopped" | "expired" | "offline" | "idle";
export type ErrorCode =
  | "not_found"
  | "bad_key"
  | "full"
  | "rate_limited"
  | "version"
  | "too_large"
  | "unauthorized"
  | "conflict"
  | "too_many_shares"
  | "bad_request";

export type ViewerEvent =
  | { t: "waiting" }
  | { t: "joined"; access: Access; cols: number; rows: number }
  | { t: "reset" }
  | { t: "write"; data: Bytes }
  | { t: "resized"; cols: number; rows: number }
  | { t: "access"; access: Access }
  | { t: "input_paused"; paused: boolean }
  | { t: "program_exited" }
  | { t: "sharer_away" }
  | { t: "sharer_back" }
  | { t: "expiry"; expiresAt: number }
  | { t: "denied" }
  | { t: "kicked" }
  | { t: "ended"; reason: EndReason }
  | { t: "refused"; code: ErrorCode }
  | { t: "dropped" };

export type Action = { t: "text"; text: string } | { t: "binary"; data: Bytes } | { t: "event"; event: ViewerEvent };

type State =
  | { t: "connecting" }
  | { t: "joining" }
  | { t: "handshaking"; hs: ViewerHandshake }
  | { t: "live"; access: Access; sealer: Sealer; opener: Opener }
  | { t: "done" };

const ev = (event: ViewerEvent): Action => ({ t: "event", event });
const text = (msg: object): Action => ({ t: "text", text: JSON.stringify(msg) });

/** Raw DEFLATE, bounded so a hostile chunk cannot exhaust memory. */
export async function inflateRaw(data: Bytes): Promise<Bytes> {
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > CHUNK_INFLATED_MAX) {
      await reader.cancel();
      throw new Error("snapshot chunk too large");
    }
    parts.push(value);
  }
  return concat(...parts);
}

export class ViewerEngine {
  private state: State = { t: "connecting" };
  private viewerId = 0;
  private lastSeq: bigint | null = null;
  private holding = false;
  private held: Array<[bigint, Bytes]> = [];
  private assembly: { key: string; chunks: Array<Bytes | null> } | null = null;

  private constructor(
    private readonly shareId: Bytes,
    private readonly keys: LinkKeys,
    private readonly client: Bytes,
  ) {}

  static async create(shareId: Bytes, secret: Bytes, client: Bytes): Promise<ViewerEngine> {
    return new ViewerEngine(shareId, await deriveKeys(secret), client);
  }

  get isLive(): boolean {
    return this.state.t === "live";
  }

  get canType(): boolean {
    return this.state.t === "live" && this.state.access === "type";
  }

  /** The connection dropped. `false` when the outcome is final. */
  connectionLost(): boolean {
    if (this.state.t === "done") return false;
    this.state = { t: "connecting" };
    this.holding = false;
    this.held = [];
    this.assembly = null;
    return true;
  }

  async onText(raw: string): Promise<Action[]> {
    let msg: { t?: string; [k: string]: unknown };
    try {
      msg = JSON.parse(raw);
    } catch {
      return [];
    }
    switch (msg.t) {
      case "hello": {
        const challenge = fromB64(String(msg.challenge), 32);
        if (!challenge) return this.finish({ t: "refused", code: "bad_request" });
        if (msg.proto !== PROTOCOL_VERSION) return this.finish({ t: "refused", code: "version" });
        this.state = { t: "joining" };
        const proof = await prove(this.keys, ROLE_VIEWER, this.shareId, challenge);
        return [
          text({
            t: "join",
            proto: PROTOCOL_VERSION,
            share_id: toB64(this.shareId),
            link_id: toB64(this.keys.linkId),
            proof: toB64(proof),
          }),
        ];
      }
      case "accepted": {
        this.viewerId = Number(msg.viewer);
        const hello: { client: string; resume_from?: number } = { client: toB64(this.client) };
        if (this.lastSeq !== null) hello.resume_from = Number(this.lastSeq);
        const [hs, msg1] = await ViewerHandshake.start(this.shareId, this.keys.psk, utf8(JSON.stringify(hello)));
        this.state = { t: "handshaking", hs };
        return [
          { t: "binary", data: msg1 },
          ev({ t: "waiting" }),
          ev({ t: "expiry", expiresAt: Number(msg.expires_at) }),
        ];
      }
      case "sharer_away":
        return [ev({ t: "sharer_away" })];
      case "sharer_back": {
        const actions: Action[] = [ev({ t: "sharer_back" })];
        const resync = await this.seal({ t: "resync", lastSeq: this.lastSeq });
        if (resync) actions.push(resync);
        return actions;
      }
      case "expiry":
        return [ev({ t: "expiry", expiresAt: Number(msg.expires_at) })];
      case "denied":
        return this.finish({ t: "denied" });
      case "kicked":
        return this.finish({ t: "kicked" });
      case "ended":
        return this.finish({ t: "ended", reason: msg.reason as EndReason });
      case "error":
        return this.finish({ t: "refused", code: msg.code as ErrorCode });
      default:
        return [];
    }
  }

  private finish(event: ViewerEvent): Action[] {
    this.state = { t: "done" };
    return [ev(event)];
  }

  async onBinary(data: Bytes): Promise<Action[]> {
    const state = this.state;
    if (state.t === "handshaking") return this.onWelcome(state.hs, data);
    if (state.t !== "live") return [ev({ t: "dropped" })];
    let content: Content;
    try {
      content = decode(await state.opener.open(data));
    } catch {
      return [ev({ t: "dropped" })];
    }
    return this.onContent(content);
  }

  private async onWelcome(hs: ViewerHandshake, data: Bytes): Promise<Action[]> {
    let welcome: { access: Access; cols: number; rows: number };
    let session;
    try {
      const [keys, body] = await hs.finish(data);
      session = keys;
      welcome = JSON.parse(new TextDecoder().decode(body));
    } catch {
      return this.finish({ t: "refused", code: "bad_key" });
    }
    const binding = (direction: number) => ({ shareId: this.shareId, viewerId: this.viewerId, direction });
    this.state = {
      t: "live",
      access: welcome.access,
      sealer: await Sealer.create(session.toSharer, binding(DIR_TO_SHARER)),
      opener: await Opener.create(session.toViewer, binding(DIR_TO_VIEWER)),
    };
    // A new viewer always gets a snapshot first; hold live output until then.
    this.holding = this.lastSeq === null;
    return [ev({ t: "joined", access: welcome.access, cols: welcome.cols, rows: welcome.rows })];
  }

  private async onContent(c: Content): Promise<Action[]> {
    switch (c.t) {
      case "output":
        return this.onOutput(c.seq, c.data);
      case "snapshot":
        return this.onSnapshotChunk(c);
      case "status": {
        const actions: Action[] = [];
        if (c.status.access) {
          if (this.state.t === "live") this.state.access = c.status.access;
          actions.push(ev({ t: "access", access: c.status.access }));
        }
        if (c.status.input_paused !== undefined) {
          actions.push(ev({ t: "input_paused", paused: c.status.input_paused }));
        }
        if (c.status.program_exited) actions.push(ev({ t: "program_exited" }));
        return actions;
      }
      case "size":
        return [ev({ t: "resized", cols: c.cols, rows: c.rows })];
      default:
        return [ev({ t: "dropped" })];
    }
  }

  private onOutput(seq: bigint, data: Bytes): Action[] {
    if (this.holding) {
      this.held.push([seq, data]);
      return [];
    }
    if (this.lastSeq !== null && seq <= this.lastSeq) return [];
    this.lastSeq = seq;
    return [ev({ t: "write", data })];
  }

  private async onSnapshotChunk(c: Extract<Content, { t: "snapshot" }>): Promise<Action[]> {
    if (c.count === 0 || c.index >= c.count) return [ev({ t: "dropped" })];
    const key = `${c.coversSeq}:${c.part}:${c.count}`;
    if (this.assembly?.key !== key) this.assembly = { key, chunks: new Array(c.count).fill(null) };
    try {
      this.assembly.chunks[c.index] = c.compressed ? await inflateRaw(c.data) : copy(c.data);
    } catch {
      return [ev({ t: "dropped" })];
    }
    if (this.assembly.chunks.some((x) => x === null)) {
      this.holding = true;
      return [];
    }
    const full = concat(...(this.assembly.chunks as Bytes[]));
    this.assembly = null;
    const actions: Action[] = [
      ev({ t: "reset" }),
      ev({ t: "resized", cols: c.cols, rows: c.rows }),
      ev({ t: "write", data: full }),
    ];
    this.lastSeq = c.coversSeq;
    // A screen part is followed by its full part before any later output.
    this.holding = c.part === "screen";
    if (!this.holding) {
      const held = this.held.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
      this.held = [];
      for (const [seq, data] of held) actions.push(...this.onOutput(seq, data));
    }
    return actions;
  }

  /** Encrypts one key event or paste; `null` when typing is not allowed. */
  async input(data: Bytes): Promise<Action | null> {
    if (!this.canType) return null;
    return this.seal({ t: "input", data });
  }

  ping(): Action {
    return text({ t: "ping" });
  }

  private async seal(c: Content): Promise<Action | null> {
    if (this.state.t !== "live") return null;
    return { t: "binary", data: await this.state.sealer.seal(encode(c)) };
  }
}
