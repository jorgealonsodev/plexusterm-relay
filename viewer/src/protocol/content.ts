// Frame plaintext (docs/protocol.md §5.3). Mirrors crates/protocol/src/content.rs.

import { type Bytes, bytes, concat, fromUtf8, u16, u64, utf8 } from "./bytes";

export type Access = "view" | "type";

export interface Status {
  access?: Access;
  input_paused?: boolean;
  program_exited?: boolean;
}

export type Content =
  | { t: "output"; seq: bigint; data: Bytes }
  | {
      t: "snapshot";
      coversSeq: bigint;
      cols: number;
      rows: number;
      part: "screen" | "full";
      index: number;
      count: number;
      compressed: boolean;
      data: Bytes;
    }
  | { t: "status"; status: Status }
  | { t: "size"; cols: number; rows: number }
  | { t: "input"; data: Bytes }
  | { t: "resync"; lastSeq: bigint | null };

const T_OUTPUT = 0x10;
const T_SNAPSHOT = 0x11;
const T_STATUS = 0x12;
const T_SIZE = 0x13;
const T_INPUT = 0x20;
const T_RESYNC = 0x21;

const one = (b: number): Bytes => {
  const out = bytes(1);
  out[0] = b;
  return out;
};

export function encode(c: Content): Bytes {
  switch (c.t) {
    case "output":
      return concat(one(T_OUTPUT), u64(c.seq), c.data);
    case "snapshot":
      return concat(
        one(T_SNAPSHOT),
        u64(c.coversSeq),
        u16(c.cols),
        u16(c.rows),
        one(c.part === "screen" ? 0 : 1),
        u16(c.index),
        u16(c.count),
        one(c.compressed ? 1 : 0),
        c.data,
      );
    case "status":
      return concat(one(T_STATUS), utf8(JSON.stringify(c.status)));
    case "size":
      return concat(one(T_SIZE), u16(c.cols), u16(c.rows));
    case "input":
      return concat(one(T_INPUT), c.data);
    case "resync":
      return concat(one(T_RESYNC), one(c.lastSeq === null ? 0 : 1), u64(c.lastSeq ?? 0n));
  }
}

export class MalformedContent extends Error {}

export function decode(data: Bytes): Content {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let pos = 1;
  const need = (n: number) => {
    if (pos + n > data.length) throw new MalformedContent("truncated");
  };
  const rd8 = () => (need(1), view.getUint8(pos++));
  const rd16 = () => (need(2), (pos += 2), view.getUint16(pos - 2));
  const rd64 = () => (need(8), (pos += 8), view.getBigUint64(pos - 8));
  const rest = () => data.slice(pos);
  const flag = () => {
    const v = rd8();
    if (v > 1) throw new MalformedContent("bad flag");
    return v === 1;
  };
  switch (data[0]) {
    case T_OUTPUT:
      return { t: "output", seq: rd64(), data: rest() };
    case T_SNAPSHOT: {
      const coversSeq = rd64();
      const cols = rd16();
      const rows = rd16();
      const part = flag() ? "full" : "screen";
      const index = rd16();
      const count = rd16();
      return { t: "snapshot", coversSeq, cols, rows, part, index, count, compressed: flag(), data: rest() };
    }
    case T_STATUS:
      try {
        return { t: "status", status: JSON.parse(fromUtf8(rest())) as Status };
      } catch {
        throw new MalformedContent("bad status");
      }
    case T_SIZE:
      return { t: "size", cols: rd16(), rows: rd16() };
    case T_INPUT:
      return { t: "input", data: rest() };
    case T_RESYNC: {
      const present = flag();
      const seq = rd64();
      return { t: "resync", lastSeq: present ? seq : null };
    }
    default:
      throw new MalformedContent("unknown type");
  }
}
