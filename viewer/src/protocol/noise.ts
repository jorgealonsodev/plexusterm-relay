// Viewer (initiator) side of Noise_NNpsk0_25519_AESGCM_SHA256
// (docs/protocol.md §5.1). Mirrors crates/protocol/src/noise.rs, which uses
// snow; test/vectors.json pins both to the same bytes.

import { x25519 } from "@noble/curves/ed25519.js";

import { type Bytes, bytes, concat, copy, u64, utf8 } from "./bytes";
import { hmac, sha256 } from "./keys";

export const KIND_HANDSHAKE = 0x01;
const PROTOCOL_NAME = utf8("Noise_NNpsk0_25519_AESGCM_SHA256");
const PROLOGUE_LABEL = utf8("plexusterm-share v1");

export interface SessionKeys {
  toSharer: Bytes;
  toViewer: Bytes;
}

function nonce(n: bigint): Bytes {
  return concat(bytes(4), u64(n));
}

async function aesGcm(
  mode: "encrypt" | "decrypt",
  key: Bytes,
  n: bigint,
  ad: Bytes,
  data: Bytes,
): Promise<Bytes> {
  const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, [mode]);
  const params = { name: "AES-GCM", iv: nonce(n), additionalData: ad };
  const out =
    mode === "encrypt"
      ? await crypto.subtle.encrypt(params, k, data)
      : await crypto.subtle.decrypt(params, k, data);
  return new Uint8Array(out);
}

/** Noise HKDF: two or three 32-byte outputs. */
async function noiseHkdf(ck: Bytes, ikm: Bytes, count: 2 | 3): Promise<Bytes[]> {
  const temp = await hmac(ck, ikm);
  const out: Bytes[] = [];
  let prev = bytes(0);
  for (let i = 1; i <= count; i++) {
    const index = bytes(1);
    index[0] = i;
    prev = await hmac(temp, concat(prev, index));
    out.push(prev);
  }
  return out;
}

class SymmetricState {
  h: Bytes = copy(PROTOCOL_NAME);
  ck: Bytes = copy(PROTOCOL_NAME);
  k: Bytes | null = null;
  n = 0n;

  async mixHash(data: Bytes): Promise<void> {
    this.h = await sha256(concat(this.h, data));
  }

  async mixKey(ikm: Bytes): Promise<void> {
    const [ck, k] = await noiseHkdf(this.ck, ikm, 2);
    this.ck = ck!;
    this.k = k!;
    this.n = 0n;
  }

  async mixKeyAndHash(ikm: Bytes): Promise<void> {
    const [ck, h, k] = await noiseHkdf(this.ck, ikm, 3);
    this.ck = ck!;
    await this.mixHash(h!);
    this.k = k!;
    this.n = 0n;
  }

  async encryptAndHash(plaintext: Bytes): Promise<Bytes> {
    const c = this.k ? await aesGcm("encrypt", this.k, this.n++, this.h, plaintext) : plaintext;
    await this.mixHash(c);
    return c;
  }

  async decryptAndHash(ciphertext: Bytes): Promise<Bytes> {
    const p = this.k ? await aesGcm("decrypt", this.k, this.n++, this.h, ciphertext) : ciphertext;
    await this.mixHash(ciphertext);
    return p;
  }

  async split(): Promise<SessionKeys> {
    const [k1, k2] = await noiseHkdf(this.ck, bytes(0), 2);
    return { toSharer: k1!, toViewer: k2! };
  }
}

export class HandshakeError extends Error {}

export class ViewerHandshake {
  private constructor(
    private readonly state: SymmetricState,
    private readonly ephemeral: Bytes,
  ) {}

  /** Builds message 1 (with its 0x01 kind byte) carrying `payload`. */
  static async start(
    shareId: Bytes,
    psk: Bytes,
    payload: Bytes,
    ephemeral: Bytes = copy(x25519.utils.randomSecretKey()),
  ): Promise<[ViewerHandshake, Bytes]> {
    const s = new SymmetricState();
    await s.mixHash(concat(PROLOGUE_LABEL, shareId));
    await s.mixKeyAndHash(psk);
    const e = copy(x25519.getPublicKey(ephemeral));
    await s.mixHash(e);
    await s.mixKey(e);
    const body = await s.encryptAndHash(payload);
    const kind = bytes(1);
    kind[0] = KIND_HANDSHAKE;
    return [new ViewerHandshake(s, ephemeral), concat(kind, e, body)];
  }

  /** Reads message 2; returns the session keys and the sharer's payload. */
  async finish(message: Bytes): Promise<[SessionKeys, Bytes]> {
    if (message.length < 1 + 32 + 16 || message[0] !== KIND_HANDSHAKE) {
      throw new HandshakeError("malformed handshake message");
    }
    const s = this.state;
    const re = message.slice(1, 33);
    await s.mixHash(re);
    await s.mixKey(re);
    let shared: Bytes;
    try {
      shared = copy(x25519.getSharedSecret(this.ephemeral, re));
    } catch {
      throw new HandshakeError("invalid sharer key");
    }
    await s.mixKey(shared);
    let payload: Bytes;
    try {
      payload = await s.decryptAndHash(message.slice(33));
    } catch {
      throw new HandshakeError("handshake authentication failed");
    }
    return [await s.split(), payload];
  }
}
