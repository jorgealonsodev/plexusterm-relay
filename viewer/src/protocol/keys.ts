// Link key derivation and relay proofs (docs/protocol.md §2).

import { type Bytes, bytes, concat, utf8 } from "./bytes";

const SALT = utf8("plexusterm-share v1");
const PROOF_LABEL = utf8("plexusterm-share v1 proof");

export const ROLE_VIEWER = 1;

export interface LinkKeys {
  linkId: Bytes;
  psk: Bytes;
  relayAuth: Bytes;
}

async function hkdf(secret: Bytes, info: string, length: number): Promise<Bytes> {
  const key = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: SALT, info: utf8(info) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

export async function deriveKeys(secret: Bytes): Promise<LinkKeys> {
  return {
    linkId: await hkdf(secret, "link id", 16),
    psk: await hkdf(secret, "handshake psk", 32),
    relayAuth: await hkdf(secret, "relay auth", 32),
  };
}

export async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export async function hmac(key: Bytes, data: Bytes): Promise<Bytes> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

export async function verifier(keys: LinkKeys): Promise<Bytes> {
  return sha256(keys.relayAuth);
}

export async function prove(
  keys: LinkKeys,
  role: number,
  shareId: Bytes,
  challenge: Bytes,
): Promise<Bytes> {
  const roleByte = bytes(1);
  roleByte[0] = role;
  return hmac(await verifier(keys), concat(PROOF_LABEL, roleByte, shareId, challenge));
}
