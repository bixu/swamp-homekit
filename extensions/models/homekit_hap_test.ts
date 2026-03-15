import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  _N_HEX,
  bigintToBytes,
  bytesToBigint,
  CHAR_TYPES,
  coerceValue,
  extractAccessoryList,
  extractControllableServices,
  type HAPAccessoryDatabase,
  modPow,
  normalizeUUID,
  resolveCharacteristic,
  SERVICE_TYPES,
  SRP_PAD_LEN,
  SRPClient,
  tlvDecode,
  tlvEncode,
} from "./homekit_hap.ts";
import { sha512 } from "npm:@noble/hashes@1.7.2/sha512";
import { concatBytes } from "npm:@noble/hashes@1.7.2/utils";

// ─── TLV8 Tests ──────────────────────────────────────────────────────────────

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

// ─── SRP-6a Tests ────────────────────────────────────────────────────────────

const N = BigInt("0x" + _N_HEX);
const g = 5n;

Deno.test("N prime matches RFC 5054 3072-bit group", () => {
  const rfc5054_3072 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200CB" +
    "BE117577A615D6C770988C0BAD946E208E24FA074E5AB3143" +
    "DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

  assertEquals(
    _N_HEX.toUpperCase(),
    rfc5054_3072.toUpperCase(),
    "N prime does not match RFC 5054 3072-bit group",
  );
});

Deno.test("N prime is 3072 bits (768 hex chars)", () => {
  assertEquals(_N_HEX.length, 768);
});

Deno.test("SRPClient generates 384-byte public key", () => {
  const client = new SRPClient("Pair-Setup", "12345678");
  const pubKey = client.getPublicKey();

  assertEquals(pubKey.length, 384);
  const nonZero = pubKey.some((b) => b !== 0);
  assertEquals(nonZero, true);
});

Deno.test("SRPClient two instances produce different public keys", () => {
  const a = new SRPClient("Pair-Setup", "12345678");
  const b = new SRPClient("Pair-Setup", "12345678");

  const pkA = a.getPublicKey();
  const pkB = b.getPublicKey();

  let same = true;
  for (let i = 0; i < pkA.length; i++) {
    if (pkA[i] !== pkB[i]) {
      same = false;
      break;
    }
  }
  assertEquals(same, false);
});

Deno.test("SRPClient deterministic with injected private key", () => {
  const privateKey = new Uint8Array(32).fill(0x42);
  const a = new SRPClient("Pair-Setup", "12345678", privateKey);
  const b = new SRPClient("Pair-Setup", "12345678", privateKey);

  assertEquals(a.getPublicKey(), b.getPublicKey());
});

// ─── SRP Full Client-Server Round-Trip ───────────────────────────────────────

/**
 * Minimal SRP-6a server implementation for testing.
 * Mirrors the math a HomeKit accessory would perform.
 */
function srpServer(
  username: string,
  password: string,
  salt: Uint8Array,
  serverPrivateKey: Uint8Array,
) {
  const b = bytesToBigint(serverPrivateKey);

  // k = H(N | PAD(g))
  const k = bytesToBigint(
    sha512(
      concatBytes(
        bigintToBytes(N, SRP_PAD_LEN),
        bigintToBytes(g, SRP_PAD_LEN),
      ),
    ),
  );

  // x = H(salt | H(username:password))
  const identityHash = sha512(
    new TextEncoder().encode(`${username}:${password}`),
  );
  const x = bytesToBigint(sha512(concatBytes(salt, identityHash)));

  // v = g^x mod N (verifier)
  const v = modPow(g, x, N);

  // B = (k*v + g^b) mod N
  const B = ((k * v) % N + modPow(g, b, N)) % N;

  return {
    salt,
    B: bigintToBytes(B, SRP_PAD_LEN),
    /**
     * Verify client proof M1 and return server proof M2 if valid.
     */
    verify(
      clientPublicKey: Uint8Array,
      clientProof: Uint8Array,
    ): { valid: boolean; serverProof: Uint8Array } {
      const A = bytesToBigint(clientPublicKey);

      // u = H(PAD(A) | PAD(B))
      const u = bytesToBigint(
        sha512(
          concatBytes(
            bigintToBytes(A, SRP_PAD_LEN),
            bigintToBytes(B, SRP_PAD_LEN),
          ),
        ),
      );

      // S = (A * v^u)^b mod N
      const vu = modPow(v, u, N);
      const Avu = (A * vu) % N;
      const S = modPow(Avu, b, N);

      // K = H(S)
      const K = sha512(bigintToBytes(S, SRP_PAD_LEN));

      // Verify M1 = H(H(N) xor H(g) | H(I) | salt | A | B | K)
      // g is hashed as its minimal big-endian byte representation
      const hN = sha512(bigintToBytes(N, SRP_PAD_LEN));
      const hg = sha512(new Uint8Array([Number(g)]));
      const hNxorHg = new Uint8Array(hN.length);
      for (let i = 0; i < hN.length; i++) hNxorHg[i] = hN[i] ^ hg[i];
      const hI = sha512(new TextEncoder().encode(username));

      const expectedM1 = sha512(
        concatBytes(
          hNxorHg,
          hI,
          salt,
          bigintToBytes(A, SRP_PAD_LEN),
          bigintToBytes(B, SRP_PAD_LEN),
          K,
        ),
      );

      let diff = 0;
      for (let i = 0; i < expectedM1.length; i++) {
        diff |= clientProof[i] ^ expectedM1[i];
      }
      const valid = diff === 0;

      // M2 = H(A | M1 | K)
      const serverProof = sha512(
        concatBytes(bigintToBytes(A, SRP_PAD_LEN), clientProof, K),
      );

      return { valid, serverProof };
    },
  };
}

Deno.test("SRP full round-trip: client proof verified by server", () => {
  const username = "Pair-Setup";
  const password = "30522219";
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const clientPrivate = crypto.getRandomValues(new Uint8Array(32));
  const serverPrivate = crypto.getRandomValues(new Uint8Array(32));

  // Server setup
  const server = srpServer(username, password, salt, serverPrivate);

  // Client setup
  const client = new SRPClient(username, password, clientPrivate);
  client.setServerValues(server.salt, server.B);

  // Server verifies client proof
  const { valid, serverProof } = server.verify(
    client.getPublicKey(),
    client.getProof(),
  );

  assertEquals(valid, true, "Server should accept client proof");

  // Client verifies server proof
  assertEquals(
    client.verifyServerProof(serverProof),
    true,
    "Client should accept server proof",
  );
});

Deno.test("SRP round-trip: wrong password rejected", () => {
  const username = "Pair-Setup";
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const clientPrivate = crypto.getRandomValues(new Uint8Array(32));
  const serverPrivate = crypto.getRandomValues(new Uint8Array(32));

  // Server has the correct password
  const server = srpServer(username, "30522219", salt, serverPrivate);

  // Client has the wrong password
  const client = new SRPClient(username, "99999999", clientPrivate);
  client.setServerValues(server.salt, server.B);

  const { valid } = server.verify(client.getPublicKey(), client.getProof());
  assertEquals(valid, false, "Server should reject wrong password proof");
});

Deno.test("SRP round-trip: deterministic with fixed keys", () => {
  const username = "Pair-Setup";
  const password = "12345678";
  const salt = new Uint8Array(16).fill(0xaa);
  const clientPrivate = new Uint8Array(32).fill(0x11);
  const serverPrivate = new Uint8Array(32).fill(0x22);

  // Run twice and verify identical proofs
  const server1 = srpServer(username, password, salt, serverPrivate);
  const client1 = new SRPClient(username, password, clientPrivate);
  client1.setServerValues(server1.salt, server1.B);
  const proof1 = client1.getProof();

  const server2 = srpServer(username, password, salt, serverPrivate);
  const client2 = new SRPClient(username, password, clientPrivate);
  client2.setServerValues(server2.salt, server2.B);
  const proof2 = client2.getProof();

  assertEquals(proof1, proof2, "Same inputs should produce same proof");

  const { valid } = server1.verify(client1.getPublicKey(), proof1);
  assertEquals(valid, true, "Server should accept proof");
});

// ─── Characteristic Control Tests ────────────────────────────────────────────

function makeLightbulbDb(): HAPAccessoryDatabase {
  return {
    accessories: [{
      aid: 1,
      services: [
        {
          iid: 1,
          type: "3E", // AccessoryInformation
          characteristics: [
            { aid: 1, iid: 2, type: "23", value: "Test Light" },
          ],
        },
        {
          iid: 10,
          type: "43", // Lightbulb
          characteristics: [
            { aid: 1, iid: 11, type: "23", value: "Living Room Light" },
            {
              aid: 1,
              iid: 12,
              type: "25",
              value: false,
              format: "bool",
            }, // On
            {
              aid: 1,
              iid: 13,
              type: "8",
              value: 50,
              format: "int",
            }, // Brightness
            {
              aid: 1,
              iid: 14,
              type: "13",
              value: 200,
              format: "float",
            }, // Hue
            {
              aid: 1,
              iid: 15,
              type: "2F",
              value: 80,
              format: "float",
            }, // Saturation
          ],
        },
      ],
    }],
  };
}

function makeLockDb(): HAPAccessoryDatabase {
  return {
    accessories: [{
      aid: 1,
      services: [
        {
          iid: 1,
          type: "3E",
          characteristics: [
            { aid: 1, iid: 2, type: "23", value: "Front Door Lock" },
          ],
        },
        {
          iid: 10,
          type: "45", // LockMechanism
          characteristics: [
            { aid: 1, iid: 11, type: "23", value: "Front Door" },
            {
              aid: 1,
              iid: 12,
              type: "1D",
              value: 1,
              format: "uint8",
            }, // LockCurrentState
            {
              aid: 1,
              iid: 13,
              type: "1E",
              value: 1,
              format: "uint8",
            }, // LockTargetState
          ],
        },
      ],
    }],
  };
}

function makeMultiServiceDb(): HAPAccessoryDatabase {
  return {
    accessories: [{
      aid: 1,
      services: [
        {
          iid: 10,
          type: "43", // Lightbulb
          characteristics: [
            { aid: 1, iid: 11, type: "23", value: "Ceiling Light" },
            { aid: 1, iid: 12, type: "25", value: true, format: "bool" },
            { aid: 1, iid: 13, type: "8", value: 100, format: "int" },
          ],
        },
        {
          iid: 20,
          type: "49", // Switch
          characteristics: [
            { aid: 1, iid: 21, type: "23", value: "Wall Switch" },
            { aid: 1, iid: 22, type: "25", value: false, format: "bool" },
          ],
        },
      ],
    }],
  };
}

function makeSensorOnlyDb(): HAPAccessoryDatabase {
  return {
    accessories: [{
      aid: 1,
      services: [{
        iid: 10,
        type: "8A", // TemperatureSensor
        characteristics: [
          { aid: 1, iid: 11, type: "23", value: "Temp Sensor" },
          {
            aid: 1,
            iid: 12,
            type: "11",
            value: 22.5,
            unit: "celsius",
          },
        ],
      }],
    }],
  };
}

Deno.test("extractControllableServices finds lightbulb controls", () => {
  const db = makeLightbulbDb();
  const services = extractControllableServices(db);

  assertEquals(services.length, 1);
  assertEquals(services[0].serviceName, "Living Room Light");
  assertEquals(normalizeUUID(services[0].serviceType), SERVICE_TYPES.Lightbulb);

  const charNames = services[0].characteristics.map((c) => c.name);
  assertEquals(charNames.includes("On"), true);
  assertEquals(charNames.includes("Brightness"), true);
  assertEquals(charNames.includes("Hue"), true);
  assertEquals(charNames.includes("Saturation"), true);
});

Deno.test("extractControllableServices finds lock controls", () => {
  const db = makeLockDb();
  const services = extractControllableServices(db);

  assertEquals(services.length, 1);
  assertEquals(services[0].serviceName, "Front Door");

  const charNames = services[0].characteristics.map((c) => c.name);
  assertEquals(charNames.includes("LockTargetState"), true);
  // LockCurrentState is not writable, should not appear
  assertEquals(charNames.includes("LockCurrentState"), false);
});

Deno.test("extractControllableServices finds multiple services", () => {
  const db = makeMultiServiceDb();
  const services = extractControllableServices(db);

  assertEquals(services.length, 2);
  const names = services.map((s) => s.serviceName);
  assertEquals(names.includes("Ceiling Light"), true);
  assertEquals(names.includes("Wall Switch"), true);
});

Deno.test("extractControllableServices returns empty for sensor-only", () => {
  const db = makeSensorOnlyDb();
  const services = extractControllableServices(db);

  assertEquals(services.length, 0);
});

Deno.test("extractControllableServices includes aid and iid", () => {
  const db = makeLightbulbDb();
  const services = extractControllableServices(db);
  const onChar = services[0].characteristics.find((c) => c.name === "On")!;

  assertEquals(onChar.aid, 1);
  assertEquals(onChar.iid, 12);
  assertEquals(onChar.format, "bool");
});

Deno.test("resolveCharacteristic finds On in lightbulb", () => {
  const db = makeLightbulbDb();
  const result = resolveCharacteristic(db, "On");

  assertEquals(result !== null, true);
  assertEquals(result!.aid, 1);
  assertEquals(result!.iid, 12);
  assertEquals(result!.name, "On");
  assertEquals(result!.format, "bool");
});

Deno.test("resolveCharacteristic finds Brightness in lightbulb", () => {
  const db = makeLightbulbDb();
  const result = resolveCharacteristic(db, "Brightness");

  assertEquals(result !== null, true);
  assertEquals(result!.iid, 13);
});

Deno.test("resolveCharacteristic is case-insensitive", () => {
  const db = makeLightbulbDb();
  const lower = resolveCharacteristic(db, "on");
  const upper = resolveCharacteristic(db, "ON");
  const mixed = resolveCharacteristic(db, "oN");

  assertEquals(lower !== null, true);
  assertEquals(upper !== null, true);
  assertEquals(mixed !== null, true);
  assertEquals(lower!.iid, upper!.iid);
  assertEquals(lower!.iid, mixed!.iid);
});

Deno.test("resolveCharacteristic filters by service name", () => {
  const db = makeMultiServiceDb();

  const ceiling = resolveCharacteristic(db, "On", "Ceiling");
  assertEquals(ceiling !== null, true);
  assertEquals(ceiling!.iid, 12);

  const wall = resolveCharacteristic(db, "On", "Wall");
  assertEquals(wall !== null, true);
  assertEquals(wall!.iid, 22);
});

Deno.test("resolveCharacteristic returns null for unknown characteristic", () => {
  const db = makeLightbulbDb();
  const result = resolveCharacteristic(db, "NonExistent");

  assertEquals(result, null);
});

Deno.test("resolveCharacteristic returns null for read-only characteristic", () => {
  const db = makeLockDb();
  // LockCurrentState exists but is not writable
  const result = resolveCharacteristic(db, "LockCurrentState");

  assertEquals(result, null);
});

Deno.test("resolveCharacteristic returns null when service name doesn't match", () => {
  const db = makeMultiServiceDb();
  const result = resolveCharacteristic(db, "On", "Bedroom");

  assertEquals(result, null);
});

// ─── coerceValue Tests ───────────────────────────────────────────────────────

Deno.test("coerceValue: bool format from boolean", () => {
  assertEquals(coerceValue(true, "bool"), true);
  assertEquals(coerceValue(false, "bool"), false);
});

Deno.test("coerceValue: bool format from number", () => {
  assertEquals(coerceValue(1, "bool"), true);
  assertEquals(coerceValue(0, "bool"), false);
  assertEquals(coerceValue(42, "bool"), true);
});

Deno.test("coerceValue: bool format from string", () => {
  assertEquals(coerceValue("true", "bool"), true);
  assertEquals(coerceValue("1", "bool"), true);
  assertEquals(coerceValue("on", "bool"), true);
  assertEquals(coerceValue("false", "bool"), false);
  assertEquals(coerceValue("0", "bool"), false);
  assertEquals(coerceValue("off", "bool"), false);
});

Deno.test("coerceValue: uint8 format from number", () => {
  assertEquals(coerceValue(0, "uint8"), 0);
  assertEquals(coerceValue(255, "uint8"), 255);
});

Deno.test("coerceValue: uint8 format from boolean", () => {
  assertEquals(coerceValue(true, "uint8"), 1);
  assertEquals(coerceValue(false, "uint8"), 0);
});

Deno.test("coerceValue: uint8 format from string", () => {
  assertEquals(coerceValue("75", "uint8"), 75);
  assertEquals(coerceValue("0", "uint8"), 0);
});

Deno.test("coerceValue: float format", () => {
  assertEquals(coerceValue(22.5, "float"), 22.5);
  assertEquals(coerceValue("22.5", "float"), 22.5);
  assertEquals(coerceValue(true, "float"), 1);
});

Deno.test("coerceValue: int format", () => {
  assertEquals(coerceValue(100, "int"), 100);
  assertEquals(coerceValue("50", "int"), 50);
});

Deno.test("coerceValue: unknown format returns value unchanged", () => {
  assertEquals(coerceValue("hello", undefined), "hello");
  assertEquals(coerceValue(42, undefined), 42);
  assertEquals(coerceValue(true, undefined), true);
});

// ─── normalizeUUID Tests ─────────────────────────────────────────────────────

Deno.test("normalizeUUID: short UUID", () => {
  assertEquals(normalizeUUID("25"), "25");
  assertEquals(normalizeUUID("8"), "8");
  assertEquals(normalizeUUID("8A"), "8A");
});

Deno.test("normalizeUUID: full UUID extracts significant part", () => {
  assertEquals(
    normalizeUUID("00000025-0000-1000-8000-0026BB765291"),
    "25",
  );
  assertEquals(
    normalizeUUID("0000008A-0000-1000-8000-0026BB765291"),
    "8A",
  );
});

Deno.test("normalizeUUID: case normalization", () => {
  assertEquals(normalizeUUID("8a"), "8A");
  assertEquals(normalizeUUID("ce"), "CE");
});

// ─── CHAR_TYPES / SERVICE_TYPES Tests ────────────────────────────────────────

Deno.test("CHAR_TYPES contains expected writable characteristics", () => {
  assertEquals(CHAR_TYPES.On, "25");
  assertEquals(CHAR_TYPES.Brightness, "8");
  assertEquals(CHAR_TYPES.LockTargetState, "1E");
  assertEquals(CHAR_TYPES.TargetTemperature, "35");
  assertEquals(CHAR_TYPES.TargetDoorState, "32");
  assertEquals(CHAR_TYPES.TargetPosition, "7C");
  assertEquals(CHAR_TYPES.Active, "B0");
});

Deno.test("SERVICE_TYPES contains expected controllable services", () => {
  assertEquals(SERVICE_TYPES.Lightbulb, "43");
  assertEquals(SERVICE_TYPES.Switch, "49");
  assertEquals(SERVICE_TYPES.LockMechanism, "45");
  assertEquals(SERVICE_TYPES.Thermostat, "4A");
  assertEquals(SERVICE_TYPES.GarageDoorOpener, "41");
});

// ─── extractAccessoryList Tests ──────────────────────────────────────────────

Deno.test("extractAccessoryList returns accessory name from AccessoryInformation", () => {
  const db = makeLightbulbDb();
  const list = extractAccessoryList(db);

  assertEquals(list.length, 1);
  assertEquals(list[0].name, "Test Light");
  assertEquals(list[0].aid, 1);
});

Deno.test("extractAccessoryList skips AccessoryInformation and ProtocolInformation services", () => {
  const db: HAPAccessoryDatabase = {
    accessories: [{
      aid: 1,
      services: [
        {
          iid: 1,
          type: "3E", // AccessoryInformation
          characteristics: [
            { aid: 1, iid: 2, type: "23", value: "Device" },
          ],
        },
        {
          iid: 5,
          type: "A2", // ProtocolInformation
          characteristics: [
            { aid: 1, iid: 6, type: "37", value: "1.1.0" },
          ],
        },
        {
          iid: 10,
          type: "43", // Lightbulb
          characteristics: [
            { aid: 1, iid: 11, type: "23", value: "Light" },
            { aid: 1, iid: 12, type: "25", value: true, format: "bool" },
          ],
        },
      ],
    }],
  };
  const list = extractAccessoryList(db);

  assertEquals(list[0].services.length, 1);
  assertEquals(list[0].services[0].typeName, "Lightbulb");
});

Deno.test("extractAccessoryList includes all service types", () => {
  const db = makeMultiServiceDb();
  const list = extractAccessoryList(db);

  assertEquals(list[0].services.length, 2);
  assertEquals(list[0].services[0].typeName, "Lightbulb");
  assertEquals(list[0].services[1].typeName, "Switch");
});

Deno.test("extractAccessoryList marks writable characteristics", () => {
  const db = makeLightbulbDb();
  const list = extractAccessoryList(db);
  const lightSvc = list[0].services[0];

  const onChar = lightSvc.characteristics.find((c) => c.name === "On")!;
  assertEquals(onChar.writable, true);

  const brightnessChar = lightSvc.characteristics.find((c) =>
    c.name === "Brightness"
  )!;
  assertEquals(brightnessChar.writable, true);
});

Deno.test("extractAccessoryList marks read-only characteristics", () => {
  const db = makeLockDb();
  const list = extractAccessoryList(db);
  const lockSvc = list[0].services[0];

  const currentState = lockSvc.characteristics.find((c) =>
    c.name === "LockCurrentState"
  )!;
  assertEquals(currentState.writable, false);

  const targetState = lockSvc.characteristics.find((c) =>
    c.name === "LockTargetState"
  )!;
  assertEquals(targetState.writable, true);
});

Deno.test("extractAccessoryList includes sensor services", () => {
  const db = makeSensorOnlyDb();
  const list = extractAccessoryList(db);

  assertEquals(list[0].services.length, 1);
  assertEquals(list[0].services[0].typeName, "TemperatureSensor");

  const tempChar = list[0].services[0].characteristics.find((c) =>
    c.name === "CurrentTemperature"
  )!;
  assertEquals(tempChar.value, 22.5);
  assertEquals(tempChar.unit, "celsius");
  assertEquals(tempChar.writable, false);
});

Deno.test("extractAccessoryList excludes Name characteristic from service chars", () => {
  const db = makeLightbulbDb();
  const list = extractAccessoryList(db);
  const lightSvc = list[0].services[0];

  // Name is used as service name, not included in characteristics
  assertEquals(lightSvc.name, "Living Room Light");
  const nameChar = lightSvc.characteristics.find((c) => c.name === "Name");
  assertEquals(nameChar, undefined);
});

Deno.test("extractAccessoryList preserves characteristic metadata", () => {
  const db = makeLightbulbDb();
  const list = extractAccessoryList(db);
  const brightChar = list[0].services[0].characteristics.find((c) =>
    c.name === "Brightness"
  )!;

  assertEquals(brightChar.iid, 13);
  assertEquals(brightChar.format, "int");
  assertEquals(brightChar.value, 50);
});

Deno.test("extractAccessoryList fallback name when no AccessoryInformation", () => {
  const db: HAPAccessoryDatabase = {
    accessories: [{
      aid: 3,
      services: [{
        iid: 10,
        type: "43",
        characteristics: [
          { aid: 3, iid: 12, type: "25", value: true, format: "bool" },
        ],
      }],
    }],
  };
  const list = extractAccessoryList(db);

  assertEquals(list[0].name, "Accessory 3");
  assertEquals(list[0].services[0].name, "Lightbulb 3.10");
});
