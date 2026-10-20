// Encrypted frames (docs/protocol.md §5.2). Mirrors crates/protocol/src/frame.rs.

import { type Bytes, bytes, concat, u32, u64, utf8 } from "./bytes";

export const KIND_FRAME = 0x02;
export const DIR_TO_VIEWER = 0;
export const DIR_TO_SHARER = 1;
const AAD_LABEL = utf8("PTS1");
const MAX_PLAINTEXT = 32 * 1024;

export interface Binding {
  shareId: Bytes;
  viewerId: number;
  direction: number;
}

export class FrameError extends Error {
  constructor(readonly reason: "malformed" | "replay" | "auth" | "too_large") {
    super(reason);
  }
}

function aad(b: Binding, seq: bigint): Bytes {
  const dir = bytes(1);
  dir[0] = b.direction;
  return concat(AAD_LABEL, b.shareId, u32(b.viewerId), dir, u64(seq));
}

const nonce = (seq: bigint): Bytes => concat(bytes(4), u64(seq));

async function importKey(key: Bytes, use: KeyUsage): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", key, "AES-GCM", false, [use]);
}

export class Sealer {
  private nextSeq = 1n;
  private constructor(
    private readonly key: CryptoKey,
    private readonly binding: Binding,
  ) {}

  static async create(key: Bytes, binding: Binding): Promise<Sealer> {
    return new Sealer(await importKey(key, "encrypt"), binding);
  }

  async seal(plaintext: Bytes): Promise<Bytes> {
    if (plaintext.length > MAX_PLAINTEXT) throw new FrameError("too_large");
    const seq = this.nextSeq++;
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce(seq), additionalData: aad(this.binding, seq) },
      this.key,
      plaintext,
    );
    const kind = bytes(1);
    kind[0] = KIND_FRAME;
    return concat(kind, u64(seq), new Uint8Array(ct));
  }
}

export class Opener {
  private lastSeq = 0n;
  private constructor(
    private readonly key: CryptoKey,
    private readonly binding: Binding,
  ) {}

  static async create(key: Bytes, binding: Binding): Promise<Opener> {
    return new Opener(await importKey(key, "decrypt"), binding);
  }

  async open(frame: Bytes): Promise<Bytes> {
    if (frame.length < 9 || frame[0] !== KIND_FRAME) throw new FrameError("malformed");
    const seq = new DataView(frame.buffer, frame.byteOffset + 1, 8).getBigUint64(0);
    if (seq <= this.lastSeq) throw new FrameError("replay");
    let plaintext: ArrayBuffer;
    try {
      plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce(seq), additionalData: aad(this.binding, seq) },
        this.key,
        frame.slice(9),
      );
    } catch {
      throw new FrameError("auth");
    }
    // Only an authenticated frame advances the window.
    this.lastSeq = seq;
    return new Uint8Array(plaintext);
  }
}
