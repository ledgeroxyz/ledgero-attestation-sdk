import { describe, expect, it } from "vitest";
import { keccak256, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  ATTESTATION_SCHEMA_VERSION,
  createAttestationDomain,
  createOffchainAttestation,
  hashAttestationContent,
  signAttestation,
  toSignedAttestationPayload,
  verifyAttestation,
  ZERO_ADDRESS,
  type AttestationContent,
} from "../src/index.js";

const TEST_PRIVATE_KEY = "0x4dc3172729ffb3af5a2c5454cbed3b658b274a2ed0be0d898602d81f542fa7ab" as const;
const testAccount = privateKeyToAccount(TEST_PRIVATE_KEY);

const domain = createAttestationDomain({
  chainId: 8453,
  verifyingContract: "0x1234567890123456789012345678901234567890",
});

function sampleContent(overrides: Partial<AttestationContent> = {}): AttestationContent {
  return {
    assetId: "asset_9f2c1a7b4e6d4c3fa1b2c3d4e5f60718",
    name: "Series A Invoice — Acme Corp",
    assetClass: "invoice",
    claimedValue: 250_000,
    score: 72,
    rating: "B",
    issuedAt: "2026-07-18T10:20:30.000Z",
    ...overrides,
  };
}

describe("toSignedAttestationPayload — field derivation", () => {
  it("derives on-chain fields from off-chain content with sensible defaults", () => {
    const content = sampleContent();
    const payload = toSignedAttestationPayload(content, { underwriter: testAccount.address });

    expect(payload.schemaVersion).toBe(ATTESTATION_SCHEMA_VERSION);
    expect(payload.assetId).toBe(keccak256(stringToHex(content.assetId)));
    expect(payload.assetClass).toBe("invoice");
    expect(payload.riskScore).toBe(720); // 72 * 10
    expect(payload.riskTier).toBe("B");
    expect(payload.issuedAt).toBe(Math.floor(Date.parse(content.issuedAt) / 1000));
    expect(payload.underwriter).toBe(testAccount.address);
    expect(payload.subject).toBe(ZERO_ADDRESS);
    expect(payload.expiresAt).toBe(0);
    expect(payload.nonce).toBe(0n);
  });

  it("commits supportingData to the off-chain SHA-256 content hash by default", () => {
    const content = sampleContent();
    const payload = toSignedAttestationPayload(content, { underwriter: testAccount.address });

    expect(payload.supportingData).toHaveLength(1);
    const ref = payload.supportingData[0]!;
    expect(ref.label).toBe("offchain-attestation-content");
    expect(ref.hash).toBe(`0x${hashAttestationContent(content)}`);
  });

  it("uses the attestationId in the supporting-data uri when present", () => {
    const att = createOffchainAttestation(sampleContent(), { attestationId: "att_abc123" });
    const payload = toSignedAttestationPayload(att, { underwriter: testAccount.address });
    expect(payload.supportingData[0]!.uri).toBe("ledgero:attestation/att_abc123");
  });

  it("maps an unrecognized assetClass to 'other'", () => {
    const payload = toSignedAttestationPayload(
      sampleContent({ assetClass: "collectible" }),
      { underwriter: testAccount.address },
    );
    expect(payload.assetClass).toBe("other");
  });

  it("passes through recognized dapp asset classes and A/B/C/D ratings directly", () => {
    for (const [cls, rating] of [
      ["real_estate", "A"],
      ["receivable", "C"],
      ["inventory", "D"],
    ] as const) {
      const payload = toSignedAttestationPayload(
        sampleContent({ assetClass: cls, rating }),
        { underwriter: testAccount.address },
      );
      expect(payload.assetClass).toBe(cls);
      expect(payload.riskTier).toBe(rating);
    }
  });

  it("honors explicit overrides in extra", () => {
    const payload = toSignedAttestationPayload(sampleContent(), {
      underwriter: testAccount.address,
      subject: testAccount.address,
      nonce: 42n,
      expiresAt: 1_900_000_000,
      schemaVersion: 9,
      assetId: `0x${"ab".repeat(32)}`,
      assetClass: "real_estate",
      riskScore: 999,
      riskTier: "AAA",
      issuedAt: 1_700_000_000,
      supportingData: [],
    });

    expect(payload.subject).toBe(testAccount.address);
    expect(payload.nonce).toBe(42n);
    expect(payload.expiresAt).toBe(1_900_000_000);
    expect(payload.schemaVersion).toBe(9);
    expect(payload.assetId).toBe(`0x${"ab".repeat(32)}`);
    expect(payload.assetClass).toBe("real_estate");
    expect(payload.riskScore).toBe(999);
    expect(payload.riskTier).toBe("AAA");
    expect(payload.issuedAt).toBe(1_700_000_000);
    expect(payload.supportingData).toEqual([]);
  });

  it("throws on an unmappable rating when no override is given", () => {
    expect(() =>
      toSignedAttestationPayload(sampleContent({ rating: "gold" }), { underwriter: testAccount.address }),
    ).toThrow(/RiskTier/);
  });

  it("accepts an unmappable rating when extra.riskTier is provided", () => {
    const payload = toSignedAttestationPayload(sampleContent({ rating: "gold" }), {
      underwriter: testAccount.address,
      riskTier: "BBB",
    });
    expect(payload.riskTier).toBe("BBB");
  });

  it("throws on an unparseable issuedAt when no override is given", () => {
    expect(() =>
      toSignedAttestationPayload(sampleContent({ issuedAt: "not-a-date" }), {
        underwriter: testAccount.address,
      }),
    ).toThrow(/issuedAt/);
  });
});

describe("round-trip: off-chain -> upgrade -> sign -> verify", () => {
  it("promotes a dapp off-chain attestation and the resulting signature verifies", async () => {
    // 1. Issue an off-chain attestation, exactly as the dapp would.
    const att = createOffchainAttestation(sampleContent());
    expect(att.contentHash).toBe(hashAttestationContent(sampleContent()));

    // 2. Promote it to a full signable payload.
    const payload = toSignedAttestationPayload(att, {
      underwriter: testAccount.address,
      subject: ZERO_ADDRESS,
      nonce: 1n,
    });

    // 3. Sign as EIP-712 typed data.
    const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);
    expect(signature).toMatch(/^0x[0-9a-f]{130}$/);

    // 4. Verify — recovers the underwriter and passes.
    const result = await verifyAttestation(payload, domain, signature);
    expect(result.valid).toBe(true);
    expect(result.signer?.toLowerCase()).toBe(testAccount.address.toLowerCase());
  });

  it("tampering with the promoted payload breaks verification", async () => {
    const att = createOffchainAttestation(sampleContent());
    const payload = toSignedAttestationPayload(att, { underwriter: testAccount.address, nonce: 1n });
    const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);

    const tampered = { ...payload, riskScore: payload.riskScore + 1 };
    const result = await verifyAttestation(tampered, domain, signature);
    expect(result.valid).toBe(false);
  });
});
