/**
 * Pure TypeScript HomeKit Accessory Protocol (HAP) implementation.
 *
 * Implements TLV8, SRP-6a, Pair-Setup, Pair-Verify, and encrypted
 * HTTP sessions using only @noble/* crypto libraries and native BigInt.
 */

import { ed25519, x25519 } from "npm:@noble/curves@1.8.2/ed25519";
import { hkdf } from "npm:@noble/hashes@1.7.2/hkdf";
import { sha512 } from "npm:@noble/hashes@1.7.2/sha512";
import { chacha20poly1305 } from "npm:@noble/ciphers@1.2.1/chacha";
import { concatBytes } from "npm:@noble/hashes@1.7.2/utils";

// ─── TLV8 ────────────────────────────────────────────────────────────────────

const TLV = {
  Method: 0x00,
  Identifier: 0x01,
  Salt: 0x02,
  PublicKey: 0x03,
  Proof: 0x04,
  EncryptedData: 0x05,
  State: 0x06,
  Error: 0x07,
  Signature: 0x0a,
} as const;

const TLV_ERROR_NAMES: Record<number, string> = {
  0x01: "kTLVError_Unknown",
  0x02: "kTLVError_Authentication",
  0x03: "kTLVError_Backoff",
  0x04: "kTLVError_MaxPeers",
  0x05: "kTLVError_MaxTries",
  0x06: "kTLVError_Unavailable",
  0x07: "kTLVError_Busy",
};

export function tlvEncode(entries: [number, Uint8Array][]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const [type, value] of entries) {
    let offset = 0;
    do {
      const len = Math.min(value.length - offset, 255);
      chunks.push(new Uint8Array([type, len]));
      if (len > 0) chunks.push(value.slice(offset, offset + len));
      offset += len;
    } while (offset < value.length);
    if (value.length === 0) {
      chunks.push(new Uint8Array([type, 0]));
    }
  }
  return concatBytes(...chunks);
}

export function tlvDecode(data: Uint8Array): Map<number, Uint8Array> {
  const result = new Map<number, Uint8Array>();
  let i = 0;
  while (i < data.length) {
    const type = data[i];
    const length = data[i + 1];
    const value = data.slice(i + 2, i + 2 + length);
    i += 2 + length;
    const existing = result.get(type);
    if (existing) {
      result.set(type, concatBytes(existing, value));
    } else {
      result.set(type, value);
    }
  }
  return result;
}

// ─── BigInt helpers ──────────────────────────────────────────────────────────

const SRP_PAD_LEN = 384; // 3072 bits = 384 bytes

function bigintToBytes(n: bigint, length: number): Uint8Array {
  const hex = n.toString(16).padStart(length * 2, "0");
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToBigint(bytes: Uint8Array): bigint {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return BigInt("0x" + (hex || "0"));
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

// ─── SRP-6a (RFC 5054, 3072-bit) ────────────────────────────────────────────

const _N_HEX =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7E" +
  "DEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF" +
  "0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552" +
  "BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE" +
  "3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581" +
  "7183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507" +
  "A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1" +
  "E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D9" +
  "8A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0B" +
  "AD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFF" +
  "FFFFFFFF";
const N = BigInt("0x" + _N_HEX);
const g = 5n;

function srpComputeK(): bigint {
  const nBytes = bigintToBytes(N, SRP_PAD_LEN);
  const gBytes = bigintToBytes(g, SRP_PAD_LEN);
  return bytesToBigint(sha512(concatBytes(nBytes, gBytes)));
}

export class SRPClient {
  private a: bigint;
  private A: bigint;
  private K!: Uint8Array;
  private M1!: Uint8Array;
  private salt!: Uint8Array;
  private B!: bigint;
  private username: string;
  private password: string;

  constructor(username: string, password: string) {
    this.username = username;
    this.password = password;
    // Generate random private key a (256 bits)
    const aBytes = crypto.getRandomValues(new Uint8Array(32));
    this.a = bytesToBigint(aBytes);
    // Compute public key A = g^a mod N
    this.A = modPow(g, this.a, N);
  }

  getPublicKey(): Uint8Array {
    return bigintToBytes(this.A, SRP_PAD_LEN);
  }

  setServerValues(salt: Uint8Array, serverPublicKey: Uint8Array): void {
    this.salt = salt;
    this.B = bytesToBigint(serverPublicKey);

    if (this.B % N === 0n) throw new Error("SRP: server sent invalid B=0");

    const k = srpComputeK();

    // u = H(PAD(A) | PAD(B))
    const u = bytesToBigint(
      sha512(
        concatBytes(
          bigintToBytes(this.A, SRP_PAD_LEN),
          bigintToBytes(this.B, SRP_PAD_LEN),
        ),
      ),
    );

    // x = H(salt | H(username:password))
    const identityHash = sha512(
      new TextEncoder().encode(`${this.username}:${this.password}`),
    );
    const x = bytesToBigint(sha512(concatBytes(salt, identityHash)));

    // S = (B - k * g^x)^(a + u*x) mod N
    const gx = modPow(g, x, N);
    const kgx = (k * gx) % N;
    const diff = ((this.B - kgx) % N + N) % N;
    const exp = (this.a + u * x) % (N - 1n);
    const S = modPow(diff, exp, N);

    // K = H(S)
    this.K = sha512(bigintToBytes(S, SRP_PAD_LEN));

    // M1 = H(H(N) xor H(g) | H(I) | salt | A | B | K)
    const hN = sha512(bigintToBytes(N, SRP_PAD_LEN));
    const hg = sha512(bigintToBytes(g, SRP_PAD_LEN));
    const hNxorHg = new Uint8Array(hN.length);
    for (let i = 0; i < hN.length; i++) hNxorHg[i] = hN[i] ^ hg[i];

    const hI = sha512(new TextEncoder().encode(this.username));

    this.M1 = sha512(
      concatBytes(
        hNxorHg,
        hI,
        salt,
        bigintToBytes(this.A, SRP_PAD_LEN),
        bigintToBytes(this.B, SRP_PAD_LEN),
        this.K,
      ),
    );
  }

  getProof(): Uint8Array {
    return this.M1;
  }

  verifyServerProof(M2: Uint8Array): boolean {
    // M2 = H(A | M1 | K)
    const expected = sha512(
      concatBytes(bigintToBytes(this.A, SRP_PAD_LEN), this.M1, this.K),
    );
    if (M2.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < M2.length; i++) diff |= M2[i] ^ expected[i];
    return diff === 0;
  }

  getSessionKey(): Uint8Array {
    return this.K;
  }
}

// ─── HAP HTTP helpers ────────────────────────────────────────────────────────

function buildHttpRequest(
  method: string,
  path: string,
  body?: Uint8Array,
  contentType = "application/pairing+tlv8",
): Uint8Array {
  const headers = [
    `${method} ${path} HTTP/1.1`,
    `Host: homekit`,
    `Content-Type: ${contentType}`,
  ];
  if (body) headers.push(`Content-Length: ${body.length}`);
  headers.push("", "");
  const headerBytes = new TextEncoder().encode(headers.join("\r\n"));
  if (body) return concatBytes(headerBytes, body);
  return headerBytes;
}

async function readHttpResponse(
  conn: Deno.TcpConn,
): Promise<{ status: number; body: Uint8Array }> {
  const buf = new Uint8Array(65536);
  let data = new Uint8Array(0);

  // Read until we have the full response
  while (true) {
    const n = await conn.read(buf);
    if (n === null) break;
    data = concatBytes(data, buf.slice(0, n));

    // Check if we have complete headers
    const headerEnd = findHeaderEnd(data);
    if (headerEnd === -1) continue;

    const headerStr = new TextDecoder().decode(data.slice(0, headerEnd));
    const contentLengthMatch = headerStr.match(/content-length:\s*(\d+)/i);

    if (contentLengthMatch) {
      const contentLength = parseInt(contentLengthMatch[1]);
      const bodyStart = headerEnd + 4; // \r\n\r\n
      while (data.length < bodyStart + contentLength) {
        const n2 = await conn.read(buf);
        if (n2 === null) break;
        data = concatBytes(data, buf.slice(0, n2));
      }
      const statusMatch = headerStr.match(/HTTP\/1\.[01]\s+(\d+)/);
      const status = statusMatch ? parseInt(statusMatch[1]) : 0;
      return { status, body: data.slice(bodyStart, bodyStart + contentLength) };
    }

    // No content-length — check for transfer-encoding: chunked or end of stream
    const statusMatch = headerStr.match(/HTTP\/1\.[01]\s+(\d+)/);
    const status = statusMatch ? parseInt(statusMatch[1]) : 0;
    if (headerStr.toLowerCase().includes("transfer-encoding: chunked")) {
      const bodyStart = headerEnd + 4;
      const decoded = decodeChunked(data.slice(bodyStart));
      return { status, body: decoded };
    }
    // No content-length and no chunked — assume body follows headers to end
    return { status, body: data.slice(headerEnd + 4) };
  }

  throw new Error("Connection closed before complete response");
}

function findHeaderEnd(data: Uint8Array): number {
  for (let i = 0; i < data.length - 3; i++) {
    if (
      data[i] === 0x0d && data[i + 1] === 0x0a &&
      data[i + 2] === 0x0d && data[i + 3] === 0x0a
    ) {
      return i;
    }
  }
  return -1;
}

function decodeChunked(data: Uint8Array): Uint8Array {
  const chunks: Uint8Array[] = [];
  let offset = 0;
  const text = new TextDecoder().decode(data);
  while (offset < text.length) {
    const lineEnd = text.indexOf("\r\n", offset);
    if (lineEnd === -1) break;
    const size = parseInt(text.slice(offset, lineEnd), 16);
    if (size === 0) break;
    const chunkStart = lineEnd + 2;
    chunks.push(data.slice(chunkStart, chunkStart + size));
    offset = chunkStart + size + 2;
  }
  return concatBytes(...chunks);
}

// ─── Encrypted session ───────────────────────────────────────────────────────

function makeNonce(counter: number): Uint8Array {
  // HAP nonce: 4 zero bytes + 8-byte little-endian counter
  const nonce = new Uint8Array(12);
  const view = new DataView(nonce.buffer);
  view.setUint32(4, counter & 0xffffffff, true);
  view.setUint32(8, Math.floor(counter / 0x100000000), true);
  return nonce;
}

export class EncryptedSession {
  private conn: Deno.TcpConn;
  private encryptKey: Uint8Array;
  private decryptKey: Uint8Array;
  private sendCounter = 0;
  private recvCounter = 0;

  constructor(
    conn: Deno.TcpConn,
    encryptKey: Uint8Array,
    decryptKey: Uint8Array,
  ) {
    this.conn = conn;
    this.encryptKey = encryptKey;
    this.decryptKey = decryptKey;
  }

  async sendEncrypted(data: Uint8Array): Promise<void> {
    // Split into frames of max 1024 bytes
    let offset = 0;
    while (offset < data.length) {
      const frameLen = Math.min(data.length - offset, 1024);
      const frame = data.slice(offset, offset + frameLen);
      offset += frameLen;

      // AAD = 2-byte little-endian length
      const aad = new Uint8Array(2);
      aad[0] = frameLen & 0xff;
      aad[1] = (frameLen >> 8) & 0xff;

      const nonce = makeNonce(this.sendCounter++);
      const cipher = chacha20poly1305(this.encryptKey, nonce, aad);
      const encrypted = cipher.encrypt(frame);

      // Send: aad(2) + encrypted(frameLen + 16 tag)
      await this.conn.write(concatBytes(aad, encrypted));
    }
  }

  async recvEncrypted(): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let done = false;

    while (!done) {
      // Read 2-byte length
      const lenBuf = new Uint8Array(2);
      await readExact(this.conn, lenBuf);
      const frameLen = lenBuf[0] | (lenBuf[1] << 8);

      // Read encrypted frame + 16-byte auth tag
      const encrypted = new Uint8Array(frameLen + 16);
      await readExact(this.conn, encrypted);

      const nonce = makeNonce(this.recvCounter++);
      const decipher = chacha20poly1305(this.decryptKey, nonce, lenBuf);
      const decrypted = decipher.decrypt(encrypted);

      chunks.push(decrypted);

      // If frame < 1024, this is the last frame
      if (frameLen < 1024) done = true;
    }

    return concatBytes(...chunks);
  }

  async request(
    method: string,
    path: string,
    // deno-lint-ignore no-explicit-any
    body?: any,
    // deno-lint-ignore no-explicit-any
  ): Promise<{ status: number; body: any }> {
    let reqBody: Uint8Array | undefined;
    if (body !== undefined) {
      reqBody = new TextEncoder().encode(JSON.stringify(body));
    }
    const req = buildHttpRequest(
      method,
      path,
      reqBody,
      "application/hap+json",
    );
    await this.sendEncrypted(req);

    const responseData = await this.recvEncrypted();
    const responseStr = new TextDecoder().decode(responseData);

    // Parse HTTP response from decrypted data
    const headerEnd = responseStr.indexOf("\r\n\r\n");
    const headerStr = responseStr.slice(0, headerEnd);
    const statusMatch = headerStr.match(/HTTP\/1\.[01]\s+(\d+)/);
    const status = statusMatch ? parseInt(statusMatch[1]) : 200;

    let responseBody = responseStr.slice(headerEnd + 4);

    // Handle chunked transfer encoding
    if (headerStr.toLowerCase().includes("transfer-encoding: chunked")) {
      const parts: string[] = [];
      let pos = 0;
      while (pos < responseBody.length) {
        const lineEnd = responseBody.indexOf("\r\n", pos);
        if (lineEnd === -1) break;
        const size = parseInt(responseBody.slice(pos, lineEnd), 16);
        if (size === 0) break;
        parts.push(responseBody.slice(lineEnd + 2, lineEnd + 2 + size));
        pos = lineEnd + 2 + size + 2;
      }
      responseBody = parts.join("");
    }

    try {
      return { status, body: JSON.parse(responseBody) };
    } catch {
      return { status, body: responseBody };
    }
  }

  close(): void {
    try {
      this.conn.close();
    } catch { /* ignore */ }
  }
}

async function readExact(
  conn: Deno.TcpConn,
  buf: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < buf.length) {
    const n = await conn.read(buf.subarray(offset));
    if (n === null) throw new Error("Connection closed unexpectedly");
    offset += n;
  }
}

// ─── Pair Setup ──────────────────────────────────────────────────────────────

export interface PairingData {
  accessoryId: string;
  accessoryLTPK: string; // hex-encoded Ed25519 public key
  clientLTSK: string; // hex-encoded Ed25519 private key
  clientLTPK: string; // hex-encoded Ed25519 public key
}

export async function pairSetup(
  host: string,
  port: number,
  setupCode: string,
): Promise<PairingData> {
  const conn = await Deno.connect({ hostname: host, port });

  try {
    // ── M1: Client → Accessory ──
    const m1 = tlvEncode([
      [TLV.State, new Uint8Array([1])],
      [TLV.Method, new Uint8Array([0])], // Pair Setup
    ]);
    await conn.write(
      buildHttpRequest("POST", "/pair-setup", m1),
    );
    const resp2 = await readHttpResponse(conn);
    const tlv2 = tlvDecode(resp2.body);

    checkTlvError(tlv2, "M2");

    const salt = tlv2.get(TLV.Salt)!;
    const serverPubKey = tlv2.get(TLV.PublicKey)!;

    // ── M3: Client → Accessory ──
    const password = setupCode.replace(/-/g, "");
    const srp = new SRPClient("Pair-Setup", password);
    srp.setServerValues(salt, serverPubKey);

    const m3 = tlvEncode([
      [TLV.State, new Uint8Array([3])],
      [TLV.PublicKey, srp.getPublicKey()],
      [TLV.Proof, srp.getProof()],
    ]);
    await conn.write(
      buildHttpRequest("POST", "/pair-setup", m3),
    );
    const resp4 = await readHttpResponse(conn);
    const tlv4 = tlvDecode(resp4.body);

    checkTlvError(tlv4, "M4");

    const serverProof = tlv4.get(TLV.Proof)!;
    if (!srp.verifyServerProof(serverProof)) {
      throw new Error("Pair Setup M4: server proof verification failed");
    }

    // ── M5: Client → Accessory (exchange long-term keys) ──
    const sessionKey = srp.getSessionKey();

    // Derive encryption key for M5
    const encSalt = new TextEncoder().encode("Pair-Setup-Encrypt-Salt");
    const encInfo = new TextEncoder().encode("Pair-Setup-Encrypt-Info");
    const encKey = hkdf(sha512, sessionKey, encSalt, encInfo, 32);

    // Generate client long-term Ed25519 keypair
    const clientLTSK = ed25519.utils.randomPrivateKey();
    const clientLTPK = ed25519.getPublicKey(clientLTSK);

    // Derive iOSDeviceX
    const ctrlSalt = new TextEncoder().encode(
      "Pair-Setup-Controller-Sign-Salt",
    );
    const ctrlInfo = new TextEncoder().encode(
      "Pair-Setup-Controller-Sign-Info",
    );
    const iOSDeviceX = hkdf(sha512, sessionKey, ctrlSalt, ctrlInfo, 32);

    // iOSDeviceInfo = iOSDeviceX | iOSDevicePairingID | iOSDeviceLTPK
    const pairingId = new TextEncoder().encode(
      bytesToHex(clientLTPK).slice(0, 36),
    );
    const iOSDeviceInfo = concatBytes(iOSDeviceX, pairingId, clientLTPK);
    const iOSDeviceSignature = ed25519.sign(iOSDeviceInfo, clientLTSK);

    // Build sub-TLV
    const subTlv = tlvEncode([
      [TLV.Identifier, pairingId],
      [TLV.PublicKey, clientLTPK],
      [TLV.Signature, iOSDeviceSignature],
    ]);

    // Encrypt sub-TLV
    const m5Nonce = new Uint8Array(12);
    m5Nonce[4] = 0x05; // "PS-Msg05"
    new TextEncoder().encodeInto("PS-Msg05", m5Nonce.subarray(4));
    const m5Cipher = chacha20poly1305(encKey, padNonce("PS-Msg05"));
    const encryptedData = m5Cipher.encrypt(subTlv);

    const m5 = tlvEncode([
      [TLV.State, new Uint8Array([5])],
      [TLV.EncryptedData, encryptedData],
    ]);
    await conn.write(
      buildHttpRequest("POST", "/pair-setup", m5),
    );
    const resp6 = await readHttpResponse(conn);
    const tlv6 = tlvDecode(resp6.body);

    checkTlvError(tlv6, "M6");

    // Decrypt M6 response to get accessory's long-term public key
    const m6Encrypted = tlv6.get(TLV.EncryptedData)!;
    const m6Decipher = chacha20poly1305(encKey, padNonce("PS-Msg06"));
    const m6Decrypted = m6Decipher.decrypt(m6Encrypted);
    const m6SubTlv = tlvDecode(m6Decrypted);

    const accessoryLTPK = m6SubTlv.get(TLV.PublicKey)!;
    const accessoryId = new TextDecoder().decode(
      m6SubTlv.get(TLV.Identifier)!,
    );

    // Verify accessory signature
    const accSalt = new TextEncoder().encode(
      "Pair-Setup-Accessory-Sign-Salt",
    );
    const accInfo = new TextEncoder().encode(
      "Pair-Setup-Accessory-Sign-Info",
    );
    const accessoryX = hkdf(sha512, sessionKey, accSalt, accInfo, 32);
    const accessoryInfo = concatBytes(
      accessoryX,
      m6SubTlv.get(TLV.Identifier)!,
      accessoryLTPK,
    );
    const accSignature = m6SubTlv.get(TLV.Signature)!;

    if (!ed25519.verify(accSignature, accessoryInfo, accessoryLTPK)) {
      throw new Error("Pair Setup M6: accessory signature verification failed");
    }

    return {
      accessoryId,
      accessoryLTPK: bytesToHex(accessoryLTPK),
      clientLTSK: bytesToHex(clientLTSK),
      clientLTPK: bytesToHex(clientLTPK),
    };
  } finally {
    try {
      conn.close();
    } catch { /* ignore */ }
  }
}

// ─── Pair Verify ─────────────────────────────────────────────────────────────

export async function pairVerify(
  host: string,
  port: number,
  pairing: PairingData,
): Promise<EncryptedSession> {
  const conn = await Deno.connect({ hostname: host, port });

  try {
    // Generate ephemeral X25519 keypair
    const ephPriv = x25519.utils.randomPrivateKey();
    const ephPub = x25519.getPublicKey(ephPriv);

    // ── M1: Client → Accessory ──
    const m1 = tlvEncode([
      [TLV.State, new Uint8Array([1])],
      [TLV.PublicKey, ephPub],
    ]);
    await conn.write(
      buildHttpRequest("POST", "/pair-verify", m1),
    );
    const resp2 = await readHttpResponse(conn);
    const tlv2 = tlvDecode(resp2.body);

    checkTlvError(tlv2, "Pair Verify M2");

    const accEphPub = tlv2.get(TLV.PublicKey)!;
    const encryptedData = tlv2.get(TLV.EncryptedData)!;

    // Compute shared secret
    const sharedSecret = x25519.getSharedSecret(ephPriv, accEphPub);

    // Derive decryption key
    const verifyKey = hkdf(
      sha512,
      sharedSecret,
      new TextEncoder().encode("Pair-Verify-Encrypt-Salt"),
      new TextEncoder().encode("Pair-Verify-Encrypt-Info"),
      32,
    );

    // Decrypt accessory's sub-TLV
    const m2Decipher = chacha20poly1305(verifyKey, padNonce("PV-Msg02"));
    const m2Decrypted = m2Decipher.decrypt(encryptedData);
    const m2SubTlv = tlvDecode(m2Decrypted);

    // Verify accessory identity
    const accId = m2SubTlv.get(TLV.Identifier)!;
    const accSignature = m2SubTlv.get(TLV.Signature)!;

    const accLTPK = hexToBytes(pairing.accessoryLTPK);
    const accInfo = concatBytes(accEphPub, accId, ephPub);

    if (!ed25519.verify(accSignature, accInfo, accLTPK)) {
      throw new Error("Pair Verify M2: accessory signature invalid");
    }

    // ── M3: Client → Accessory ──
    const clientLTSK = hexToBytes(pairing.clientLTSK);
    const clientLTPK = hexToBytes(pairing.clientLTPK);
    const clientPairingId = new TextEncoder().encode(
      pairing.accessoryId.length > 0
        ? bytesToHex(clientLTPK).slice(0, 36)
        : "client",
    );

    const clientInfo = concatBytes(ephPub, clientPairingId, accEphPub);
    const clientSignature = ed25519.sign(clientInfo, clientLTSK);

    const subTlv = tlvEncode([
      [TLV.Identifier, clientPairingId],
      [TLV.Signature, clientSignature],
    ]);

    const m3Cipher = chacha20poly1305(verifyKey, padNonce("PV-Msg03"));
    const m3Encrypted = m3Cipher.encrypt(subTlv);

    const m3 = tlvEncode([
      [TLV.State, new Uint8Array([3])],
      [TLV.EncryptedData, m3Encrypted],
    ]);
    await conn.write(
      buildHttpRequest("POST", "/pair-verify", m3),
    );
    const resp4 = await readHttpResponse(conn);
    const tlv4 = tlvDecode(resp4.body);

    checkTlvError(tlv4, "Pair Verify M4");

    // Derive session encryption keys
    const encryptKey = hkdf(
      sha512,
      sharedSecret,
      new TextEncoder().encode("Control-Salt"),
      new TextEncoder().encode("Control-Write-Encryption-Key"),
      32,
    );
    const decryptKey = hkdf(
      sha512,
      sharedSecret,
      new TextEncoder().encode("Control-Salt"),
      new TextEncoder().encode("Control-Read-Encryption-Key"),
      32,
    );

    return new EncryptedSession(conn, encryptKey, decryptKey);
  } catch (e) {
    try {
      conn.close();
    } catch { /* ignore */ }
    throw e;
  }
}

// ─── Characteristic reading ──────────────────────────────────────────────────

export interface HAPAccessoryDatabase {
  accessories: HAPAccessory[];
}

export interface HAPAccessory {
  aid: number;
  services: HAPService[];
}

export interface HAPService {
  iid: number;
  type: string;
  characteristics: HAPCharacteristic[];
}

export interface HAPCharacteristic {
  aid: number;
  iid: number;
  type: string;
  value?: number | string | boolean;
  format?: string;
  description?: string;
  unit?: string;
}

// Well-known HAP characteristic types (short UUIDs)
export const CHAR_TYPES = {
  CurrentTemperature: "11",
  CurrentRelativeHumidity: "10",
  TemperatureDisplayUnits: "36",
  Name: "23",
  StatusActive: "75",
  BatteryLevel: "68",
  ChargingState: "8F",
  StatusLowBattery: "79",
  AirQuality: "95",
  CarbonDioxideLevel: "93",
  VOCDensity: "C8",
  PM2_5Density: "C6",
  PM10Density: "C7",
  CurrentAmbientLightLevel: "6B",
  ContactSensorState: "6A",
  MotionDetected: "22",
  OccupancyDetected: "71",
  LeakDetected: "70",
  SmokeDetected: "76",
} as const;

// Service types
export const SERVICE_TYPES = {
  TemperatureSensor: "8A",
  HumiditySensor: "82",
  AirQualitySensor: "8D",
  LightSensor: "84",
  ContactSensor: "80",
  MotionSensor: "85",
  OccupancySensor: "86",
  LeakSensor: "83",
  SmokeSensor: "87",
  BatteryService: "96",
} as const;

export function normalizeUUID(type: string): string {
  // HAP uses short UUIDs like "11" which expand to
  // "00000011-0000-1000-8000-0026BB765291"
  if (type.includes("-")) {
    // Already a full UUID — extract the significant part
    return type.split("-")[0].replace(/^0+/, "").toUpperCase() || "0";
  }
  return type.toUpperCase();
}

export interface SensorReading {
  serviceName: string;
  serviceType: string;
  characteristics: {
    name: string;
    type: string;
    value: number | string | boolean;
    unit?: string;
  }[];
}

export function extractSensorReadings(
  db: HAPAccessoryDatabase,
): SensorReading[] {
  const readings: SensorReading[] = [];
  const sensorServiceTypes = new Set(
    Object.values(SERVICE_TYPES).map((t) => t.toUpperCase()),
  );

  for (const acc of db.accessories) {
    for (const svc of acc.services) {
      const svcType = normalizeUUID(svc.type);
      if (!sensorServiceTypes.has(svcType)) continue;

      const nameChar = svc.characteristics.find(
        (c) => normalizeUUID(c.type) === CHAR_TYPES.Name,
      );
      const serviceName = (nameChar?.value as string) ||
        `Sensor ${acc.aid}.${svc.iid}`;

      const charReadings: SensorReading["characteristics"] = [];
      for (const ch of svc.characteristics) {
        if (ch.value === undefined || ch.value === null) continue;
        const chType = normalizeUUID(ch.type);
        const chName = Object.entries(CHAR_TYPES).find(
          ([_, v]) => v.toUpperCase() === chType,
        );
        if (chName) {
          charReadings.push({
            name: chName[0],
            type: ch.type,
            value: ch.value,
            unit: ch.unit,
          });
        }
      }

      if (charReadings.length > 0) {
        readings.push({
          serviceName,
          serviceType: svc.type,
          characteristics: charReadings,
        });
      }
    }
  }
  return readings;
}

// ─── Utilities ───────────────────────────────────────────────────────────────

function padNonce(label: string): Uint8Array {
  // HAP nonces: 4 zero bytes + label padded/truncated to 8 bytes
  const nonce = new Uint8Array(12);
  const labelBytes = new TextEncoder().encode(label);
  nonce.set(labelBytes.slice(0, 8), 4);
  return nonce;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function checkTlvError(tlv: Map<number, Uint8Array>, stage: string): void {
  const error = tlv.get(TLV.Error);
  if (error) {
    const code = error[0];
    const name = TLV_ERROR_NAMES[code] || `Unknown(${code})`;
    throw new Error(
      `${stage}: accessory returned error ${name} (0x${
        code.toString(16).padStart(2, "0")
      })`,
    );
  }
}
