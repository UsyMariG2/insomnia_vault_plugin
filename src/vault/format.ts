/**
 * On-disk format for the new vault file.
 *
 * Goals:
 *   - Self-describing: header carries KDF algorithm and parameters so the
 *     format can grow (e.g., increase scrypt N) without another rewrite.
 *   - Length-prefixed sections: future fields can be appended without
 *     breaking older readers (they ignore trailing bytes).
 *   - Authenticated: header is included in GCM's AAD, so an attacker who
 *     swaps a scrypt header for a weaker PBKDF2 header makes decryption fail.
 *
 * Layout (big-endian unless noted):
 *
 *   bytes  field
 *   -----  ----------------------------------------------------------
 *   4      magic        ASCII "UUV1"
 *   1      versionMajor 1
 *   1      versionMinor 0
 *   2      headerLen    length of the JSON header (uint16 BE)
 *   N      header       UTF-8 JSON object — see {@link VaultHeader}
 *   12     iv           AES-GCM nonce
 *   2      saltLen      length of the KDF salt (uint16 BE)
 *   N      salt         random per-vault salt
 *   4      ctLen        length of the ciphertext (uint32 BE)
 *   N      ciphertext   AES-256-GCM ciphertext
 *   16     tag          AES-GCM authentication tag
 *
 * AAD bound into the GCM tag = magic ‖ versionMajor ‖ versionMinor ‖ header.
 * That ties the ciphertext to the exact KDF parameters used to derive its key.
 */

import { paramsToHeader, headerToParams, type KdfParams } from "./kdf";

const MAGIC = Buffer.from("UUV1", "ascii");
const VERSION_MAJOR = 1;
const VERSION_MINOR = 0;

export interface VaultHeader extends Record<string, unknown> {
  kdf: string;
}

export interface ParsedFile {
  header: VaultHeader;
  kdfParams: KdfParams;
  salt: Buffer;
  iv: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
  aad: Buffer;
}

export interface EncodeInput {
  kdfParams: KdfParams;
  salt: Buffer;
  iv: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

export interface EncodeOutput {
  bytes: Buffer;
  aad: Buffer;
}

/** Builds the AAD that MUST be passed to AES-GCM when encrypting/decrypting. */
function buildAad(headerJson: Buffer): Buffer {
  return Buffer.concat([
    MAGIC,
    Buffer.from([VERSION_MAJOR, VERSION_MINOR]),
    headerJson,
  ]);
}

export function encode(input: EncodeInput): EncodeOutput {
  const header: VaultHeader = {
    kdf: input.kdfParams.algorithm,
    ...paramsToHeader(input.kdfParams),
  };
  const headerJson = Buffer.from(JSON.stringify(header), "utf8");
  if (headerJson.length > 0xffff) {
    throw new Error("Vault header too large.");
  }
  if (input.salt.length > 0xffff) {
    throw new Error("Vault salt too large.");
  }
  if (input.ciphertext.length > 0xffffffff) {
    throw new Error("Vault ciphertext too large.");
  }
  if (input.iv.length !== 12) {
    throw new Error(`Vault IV must be 12 bytes (got ${input.iv.length}).`);
  }
  if (input.tag.length !== 16) {
    throw new Error(`Vault auth tag must be 16 bytes (got ${input.tag.length}).`);
  }

  const headerLen = Buffer.alloc(2);
  headerLen.writeUInt16BE(headerJson.length, 0);
  const saltLen = Buffer.alloc(2);
  saltLen.writeUInt16BE(input.salt.length, 0);
  const ctLen = Buffer.alloc(4);
  ctLen.writeUInt32BE(input.ciphertext.length, 0);

  const aad = buildAad(headerJson);
  const bytes = Buffer.concat([
    MAGIC,
    Buffer.from([VERSION_MAJOR, VERSION_MINOR]),
    headerLen,
    headerJson,
    input.iv,
    saltLen,
    input.salt,
    ctLen,
    input.ciphertext,
    input.tag,
  ]);
  return { bytes, aad };
}

export function decode(raw: Buffer): ParsedFile {
  if (raw.length < 4 + 2 + 2 + 12 + 2 + 4 + 16) {
    throw new Error("Vault file is too short to be valid.");
  }
  let offset = 0;

  const magic = raw.subarray(offset, offset + 4);
  offset += 4;
  if (!magic.equals(MAGIC)) {
    throw new Error("Vault file is not a UUV1 file (bad magic).");
  }

  const versionMajor = raw.readUInt8(offset++);
  const versionMinor = raw.readUInt8(offset++);
  if (versionMajor !== VERSION_MAJOR) {
    throw new Error(
      `Unsupported vault major version ${versionMajor}.${versionMinor}; this plugin understands ${VERSION_MAJOR}.x.`,
    );
  }

  const headerLen = raw.readUInt16BE(offset);
  offset += 2;
  if (offset + headerLen > raw.length) throw new Error("Vault header length exceeds file size.");
  const headerJson = raw.subarray(offset, offset + headerLen);
  offset += headerLen;

  let header: VaultHeader;
  try {
    header = JSON.parse(headerJson.toString("utf8")) as VaultHeader;
  } catch {
    throw new Error("Vault header is not valid JSON.");
  }
  const kdfParams = headerToParams(header);

  if (offset + 12 > raw.length) throw new Error("Vault IV truncated.");
  const iv = raw.subarray(offset, offset + 12);
  offset += 12;

  const saltLen = raw.readUInt16BE(offset);
  offset += 2;
  if (offset + saltLen > raw.length) throw new Error("Vault salt truncated.");
  const salt = raw.subarray(offset, offset + saltLen);
  offset += saltLen;

  const ctLen = raw.readUInt32BE(offset);
  offset += 4;
  if (offset + ctLen > raw.length) throw new Error("Vault ciphertext truncated.");
  const ciphertext = raw.subarray(offset, offset + ctLen);
  offset += ctLen;

  if (offset + 16 > raw.length) throw new Error("Vault auth tag truncated.");
  const tag = raw.subarray(offset, offset + 16);
  offset += 16;

  return {
    header,
    kdfParams,
    salt: Buffer.from(salt),
    iv: Buffer.from(iv),
    ciphertext: Buffer.from(ciphertext),
    tag: Buffer.from(tag),
    aad: buildAad(headerJson),
  };
}

export const __format_consts = { MAGIC, VERSION_MAJOR, VERSION_MINOR };
