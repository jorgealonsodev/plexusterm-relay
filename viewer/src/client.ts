// WebSocket transport around ViewerEngine: ordering, pings and reconnection
// with back-off (PRD-share §5.4).

import { type Bytes, copy, random } from "./protocol/bytes";
import { type Action, ViewerEngine, type ViewerEvent } from "./engine";

export const PING_INTERVAL_MS = 20_000;
export const BACKOFF_START_MS = 1_000;
export const BACKOFF_MAX_MS = 30_000;

export type ClientEvent =
  | ViewerEvent
  | { t: "connecting" }
  | { t: "reconnecting"; inMs: number }
  | { t: "unreachable"; inMs: number };

export interface ClientOptions {
  /** `wss://relay.example` (no trailing path). */
  relayUrl: string;
  shareId: Bytes;
  secret: Bytes;
  onEvent: (event: ClientEvent) => void;
  /** Injected in tests. */
  WebSocketImpl?: typeof WebSocket;
}

const FINAL = new Set(["denied", "kicked", "ended", "refused"]);

export class ShareClient {
  private engine: ViewerEngine | null = null;
  private ws: WebSocket | null = null;
  private chain: Promise<void> = Promise.resolve();
  private backoff = BACKOFF_START_MS;
  private ping: ReturnType<typeof setInterval> | null = null;
  private retry: ReturnType<typeof setTimeout> | null = null;
  private final = false;
  private everJoined = false;
  private sharerAway = false;
  /** Random per browser tab, so a reconnect is not counted as a new viewer. */
  private readonly client = random(16);

  constructor(private readonly opts: ClientOptions) {}

  async start(): Promise<void> {
    this.engine = await ViewerEngine.create(this.opts.shareId, this.opts.secret, this.client);
    this.connect();
  }

  /** Disconnect for good (the page is closing). */
  stop(): void {
    this.final = true;
    this.clearTimers();
    this.ws?.close(1000);
  }

  get canType(): boolean {
    return !!this.engine?.canType && !this.sharerAway && this.ws?.readyState === 1;
  }

  /** Sends one key event or one paste. Ignored when typing is not allowed. */
  input(data: Bytes): void {
    if (!this.canType) return;
    this.enqueue(async () => {
      const action = await this.engine?.input(copy(data));
      if (action && !this.sharerAway) this.execute([action]);
    });
  }

  private connect(): void {
    const Impl = this.opts.WebSocketImpl ?? WebSocket;
    this.opts.onEvent({ t: "connecting" });
    const ws = new Impl(`${this.opts.relayUrl.replace(/\/+$/, "")}/v1/viewer`);
    ws.binaryType = "arraybuffer";
    this.ws = ws;
    ws.onmessage = (m: MessageEvent) => {
      const data = m.data;
      this.enqueue(async () => {
        if (!this.engine || this.ws !== ws) return;
        const actions =
          typeof data === "string"
            ? await this.engine.onText(data)
            : await this.engine.onBinary(new Uint8Array(data as ArrayBuffer));
        this.execute(actions);
      });
    };
    ws.onopen = () => {
      this.ping = setInterval(() => this.engine && this.execute([this.engine.ping()]), PING_INTERVAL_MS);
    };
    ws.onclose = () => this.enqueue(async () => this.onClose(ws));
  }

  private enqueue(task: () => Promise<void>): void {
    this.chain = this.chain.then(task).catch(() => undefined);
  }

  private execute(actions: Action[]): void {
    for (const a of actions) {
      if (a.t === "text") this.ws?.send(a.text);
      else if (a.t === "binary") this.ws?.send(a.data);
      else this.onEngineEvent(a.event);
    }
  }

  private onEngineEvent(event: ViewerEvent): void {
    if (event.t === "joined") {
      this.everJoined = true;
      this.backoff = BACKOFF_START_MS;
    }
    if (event.t === "sharer_away") this.sharerAway = true;
    if (event.t === "sharer_back") this.sharerAway = false;
    if (FINAL.has(event.t)) {
      this.final = true;
      this.clearTimers();
    }
    this.opts.onEvent(event);
  }

  private onClose(ws: WebSocket): void {
    if (this.ws !== ws) return;
    this.clearTimers();
    this.ws = null;
    this.sharerAway = false;
    if (this.final || !this.engine?.connectionLost()) return;
    const wait = this.backoff;
    this.backoff = Math.min(this.backoff * 2, BACKOFF_MAX_MS);
    this.opts.onEvent(this.everJoined ? { t: "reconnecting", inMs: wait } : { t: "unreachable", inMs: wait });
    this.retry = setTimeout(() => this.connect(), wait);
  }

  private clearTimers(): void {
    if (this.ping) clearInterval(this.ping);
    if (this.retry) clearTimeout(this.retry);
    this.ping = null;
    this.retry = null;
  }
}
