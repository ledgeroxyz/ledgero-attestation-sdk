import { describe, expect, it } from "vitest";
import { keccak256, stringToHex, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  ATTESTATION_SCHEMA_VERSION,
  createAttestation,
  createAttestationDomain,
  decodeAttestation,
  encodeAttestation,
  hashAttestation,
  hashSupportingData,
  isExpired,
  signAttestation,
  verifyAttestation,
  ZERO_ADDRESS,
  type AttestationPayload,
} from "../src/index.js";

// Fixed, deterministic test-only private keys (32 random bytes each, not
// tied to any real funds/network). NEVER use keys like this outside of
// local tests/fixtures.
const TEST_PRIVATE_KEY = "0x4dc3172729ffb3af5a2c5454cbed3b658b274a2ed0be0d898602d81f542fa7ab" as const;
const testAccount = privateKeyToAccount(TEST_PRIVATE_KEY);

// A second, different test-only key, used to construct a "wrong signer".
const OTHER_PRIVATE_KEY = "0xcca6c6d1c0a227271cf94d672f2931acb50198fce842d47f75449bdb6150b1d9" as const;
const otherAccount = privateKeyToAccount(OTHER_PRIVATE_KEY);

const domain = createAttestationDomain({
  chainId: 8453,
  verifyingContract: "0x1234567890123456789012345678901234567890",
});

function samplePayload(overrides: Partial<AttestationPayload> = {}): AttestationPayload {
  return createAttestation({
    assetClass: "invoice",
    assetId: keccak256(stringToHex("invoice-INV-2026-0042")),
    underwriter: testAccount.address,
    subject: ZERO_ADDRESS,
    riskScore: 742,
    riskTier: "BBB",
    issuedAt: 1_800_000_000,
    expiresAt: 1_831_536_000,
    nonce: 1n,
    supportingData: [
      {
        label: "invoice-pdf",
        uri: "ipfs://bafybeigd3h2example/invoice.pdf",
        hash: keccak256(stringToHex("invoice-pdf-bytes")),
      },
      {
        label: "buyer-kyc",
        uri: "ipfs://bafybeigd3h2example/kyc.json",
        hash: keccak256(stringToHex("kyc-bytes")),
      },
    ],
    ...overrides,
  });
}

describe("createAttestation", () => {
  it("defaults schemaVersion to the current schema version", () => {
    const payload = samplePayload();
    expect(payload.schemaVersion).toBe(ATTESTATION_SCHEMA_VERSION);
  });

  it("allows overriding schemaVersion explicitly", () => {
    const payload = samplePayload({ schemaVersion: 7 });
    expect(payload.schemaVersion).toBe(7);
  });
});

describe("signAttestation / verifyAttestation", () => {
  it("signs a payload and verifies it recovers the correct signer address", async () => {
    const payload = samplePayload();
    const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);

    expect(signature).toMatch(/^0x[0-9a-f]{130}$/);

    const result = await verifyAttestation(payload, domain, signature);
    expect(result.valid).toBe(true);
    expect(result.signer?.toLowerCase()).toBe(testAccount.address.toLowerCase());
  });

  it("accepts a viem LocalAccount as the signer, equivalent to the raw private key", async () => {
    const payload = samplePayload();
    const sigFromAccount = await signAttestation(payload, domain, testAccount);
    const sigFromKey = await signAttestation(payload, domain, TEST_PRIVATE_KEY);
    expect(sigFromAccount).toBe(sigFromKey);
  });

  it("fails verification when the payload is tampered with after signing", async () => {
    const payload = samplePayload();
    const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);

    const tampered = { ...payload, riskScore: payload.riskScore + 1 };
    const result = await verifyAttestation(tampered, domain, signature);

    expect(result.valid).toBe(false);
    expect(result.reason).toBeDefined();
  });

  it("fails verification when supportingData is tampered with (changes supportingDataHash)", async () => {
    const payload = samplePayload();
    const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);

    const tampered = {
      ...payload,
      supportingData: [...payload.supportingData, { label: "extra", uri: "ipfs://extra", hash: keccak256(stringToHex("extra")) }],
    };
    const result = await verifyAttestation(tampered, domain, signature);
    expect(result.valid).toBe(false);
  });

  it("fails verification when signed by a key that doesn't match payload.underwriter", async () => {
    const payload = samplePayload(); // underwriter = testAccount.address
    const signature = await signAttestation(payload, domain, OTHER_PRIVATE_KEY);

    const result = await verifyAttestation(payload, domain, signature);
    expect(result.valid).toBe(false);
    expect(result.signer?.toLowerCase()).toBe(otherAccount.address.toLowerCase());
    expect(result.reason).toMatch(/underwriter/);
  });

  it("respects an explicit expectedSigner override", async () => {
    const payload = samplePayload();
    const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);

    const okResult = await verifyAttestation(payload, domain, signature, {
      expectedSigner: testAccount.address,
    });
    expect(okResult.valid).toBe(true);

    const badResult = await verifyAttestation(payload, domain, signature, {
      expectedSigner: otherAccount.address,
    });
    expect(badResult.valid).toBe(false);
    expect(badResult.reason).toMatch(/expectedSigner/);
  });

  it("fails verification for an expired attestation, and can skip the expiry check", async () => {
    const payload = samplePayload({ expiresAt: 1_000 }); // long past
    const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);

    const expiredResult = await verifyAttestation(payload, domain, signature, { now: 2_000 });
    expect(expiredResult.valid).toBe(false);
    expect(expiredResult.reason).toMatch(/expired/);

    const skippedResult = await verifyAttestation(payload, domain, signature, {
      now: 2_000,
      checkExpiry: false,
    });
    expect(skippedResult.valid).toBe(true);
  });

  it("a signature produced under one domain does not verify under a different domain", async () => {
    const payload = samplePayload();
    const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);

    const otherDomain = createAttestationDomain({
      chainId: 1, // different chain
      verifyingContract: domain.verifyingContract,
    });

    const result = await verifyAttestation(payload, otherDomain, signature);
    expect(result.valid).toBe(false);
  });

  it("expiresAt = 0 never expires", () => {
    const payload = samplePayload({ expiresAt: 0 });
    expect(isExpired(payload, 99_999_999_999)).toBe(false);
  });
});

describe("hashAttestation", () => {
  it("is deterministic for identical payloads", () => {
    const a = samplePayload();
    const b = samplePayload();
    expect(hashAttestation(a)).toBe(hashAttestation(b));
  });

  it("changes when any field changes", () => {
    const a = samplePayload();
    const b = samplePayload({ riskScore: a.riskScore + 1 });
    expect(hashAttestation(a)).not.toBe(hashAttestation(b));
  });

  it("changes when supportingData changes, via supportingDataHash", () => {
    const a = samplePayload();
    const b = samplePayload({
      supportingData: [a.supportingData[0]!], // drop one ref
    });
    expect(hashAttestation(a)).not.toBe(hashAttestation(b));
  });

  it("is independent of signing (no domain/signature required to compute)", () => {
    const payload = samplePayload();
    // hashAttestation takes no domain argument at all — this is really a
    // type-level guarantee, but assert it doesn't throw / needs no signature.
    expect(() => hashAttestation(payload)).not.toThrow();
  });
});

describe("hashSupportingData", () => {
  it("returns the zero hash for an empty array", () => {
    const hash = hashSupportingData([]);
    expect(hash).toBe(`0x${"0".repeat(64)}`);
  });

  it("is order-sensitive", () => {
    const payload = samplePayload();
    const reversed = [...payload.supportingData].reverse();
    expect(hashSupportingData(payload.supportingData)).not.toBe(hashSupportingData(reversed));
  });
});

describe("encodeAttestation / decodeAttestation", () => {
  it("round-trips scalar fields and the supportingDataHash commitment", () => {
    const payload = samplePayload();
    const encoded = encodeAttestation(payload);
    const decoded = decodeAttestation(encoded);

    expect(decoded.schemaVersion).toBe(payload.schemaVersion);
    expect(decoded.assetClass).toBe(payload.assetClass);
    expect(decoded.assetId).toBe(payload.assetId);
    expect(decoded.underwriter.toLowerCase()).toBe(payload.underwriter.toLowerCase());
    expect(decoded.subject.toLowerCase()).toBe(payload.subject.toLowerCase());
    expect(decoded.riskScore).toBe(payload.riskScore);
    expect(decoded.riskTier).toBe(payload.riskTier);
    expect(decoded.issuedAt).toBe(payload.issuedAt);
    expect(decoded.expiresAt).toBe(payload.expiresAt);
    expect(decoded.nonce).toBe(payload.nonce);
    expect(decoded.supportingDataHash).toBe(hashSupportingData(payload.supportingData));
  });

  it("produces deterministic bytes for identical payloads", () => {
    const a = encodeAttestation(samplePayload());
    const b = encodeAttestation(samplePayload());
    expect(a).toBe(b);
  });

  it("hashAttestation is exactly keccak256 of encodeAttestation's output", () => {
    const payload = samplePayload();
    expect(hashAttestation(payload)).toBe(keccak256(encodeAttestation(payload)));
  });

  it("toHex sanity check on assetId (fixture uses keccak256, a valid bytes32)", () => {
    const payload = samplePayload();
    expect(toHex(payload.assetId).length).toBeGreaterThan(0);
  });
});
