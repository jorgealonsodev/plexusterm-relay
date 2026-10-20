// Byte helpers shared by the protocol modules.

export type Bytes = Uint8Array<ArrayBuffer>;

export function bytes(length: number): Bytes {
  return new Uint8Array(new ArrayBuffer(length));
}

export function concat(...parts: Uint8Array[]): Bytes {
  const out = bytes(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function copy(view: Uint8Array): Bytes {
  const out = bytes(view.length);
  out.set(view);
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const utf8 = (text: string): Bytes => copy(encoder.encode(text));
export const fromUtf8 = (data: Uint8Array): string => decoder.decode(data);

export function toB64(data: Uint8Array): string {
  let binary = "";
  for (const b of data) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Unpadded base64url of exactly `length` bytes, or `null`. */
export function fromB64(text: string, length?: number): Bytes | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  let binary: string;
  try {
    binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    return null;
  }
  const out = bytes(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  if (length !== undefined && out.length !== length) return null;
  return out;
}

export function fromHex(hex: string): Bytes {
  const out = bytes(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function toHex(data: Uint8Array): string {
  return Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function u16(n: number): Bytes {
  const out = bytes(2);
  new DataView(out.buffer).setUint16(0, n);
  return out;
}

export function u32(n: number): Bytes {
  const out = bytes(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
}

export function u64(n: bigint): Bytes {
  const out = bytes(8);
  new DataView(out.buffer).setBigUint64(0, n);
  return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

export function random(length: number): Bytes {
  const out = bytes(length);
  crypto.getRandomValues(out);
  return out;
}
