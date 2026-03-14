import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { SRPClient, tlvDecode, tlvEncode } from "./homekit_hap.ts";

Deno.test("tlvEncode round-trips through tlvDecode", () => {
  const entries: [number, Uint8Array][] = [
    [0x06, new Uint8Array([1])],
    [0x03, new Uint8Array(32).fill(0xaa)],
  ];
  const encoded = tlvEncode(entries);
  const decoded = tlvDecode(encoded);

  assertEquals(decoded.get(0x06)!, new Uint8Array([1]));
  assertEquals(decoded.get(0x03)!, new Uint8Array(32).fill(0xaa));
});

Deno.test("tlvEncode handles values longer than 255 bytes", () => {
  const bigValue = new Uint8Array(300).fill(0xbb);
  const encoded = tlvEncode([[0x03, bigValue]]);
  const decoded = tlvDecode(encoded);

  assertEquals(decoded.get(0x03)!.length, 300);
  assertEquals(decoded.get(0x03)!, bigValue);
});

Deno.test("tlvEncode handles empty value", () => {
  const encoded = tlvEncode([[0x06, new Uint8Array(0)]]);
  const decoded = tlvDecode(encoded);

  assertEquals(decoded.get(0x06)!.length, 0);
});

Deno.test("SRPClient generates 384-byte public key", () => {
  const client = new SRPClient("Pair-Setup", "12345678");
  const pubKey = client.getPublicKey();

  assertEquals(pubKey.length, 384);
  // Should not be all zeros
  const nonZero = pubKey.some((b) => b !== 0);
  assertEquals(nonZero, true);
});

Deno.test("SRPClient two instances produce different public keys", () => {
  const a = new SRPClient("Pair-Setup", "12345678");
  const b = new SRPClient("Pair-Setup", "12345678");

  const pkA = a.getPublicKey();
  const pkB = b.getPublicKey();

  // Astronomically unlikely to be equal
  let same = true;
  for (let i = 0; i < pkA.length; i++) {
    if (pkA[i] !== pkB[i]) {
      same = false;
      break;
    }
  }
  assertEquals(same, false);
});
