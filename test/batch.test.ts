import { describe, expect, it } from "vitest";
import { keccak256, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  createAttestation,
  createAttestationDomain,
  signAttestation,
  verifyAttestationBatch,
  ZERO_ADDRESS,
  type AttestationPayload,
  type BatchAttestationItem,
} from "../src/index.js";

const TEST_PRIVATE_KEY = "0x4dc3172729ffb3af5a2c5454cbed3b658b274a2ed0be0d898602d81f542fa7ab" as const;
const testAccount = privateKeyToAccount(TEST_PRIVATE_KEY);

const OTHER_PRIVATE_KEY = "0xcca6c6d1c0a227271cf94d672f2931acb50198fce842d47f75449bdb6150b1d9" as const;
const otherAccount = privateKeyToAccount(OTHER_PRIVATE_KEY);

const domain = createAttestationDomain({
  chainId: 8453,
  verifyingContract: "0x1234567890123456789012345678901234567890",
});

function samplePayload(overrides: Partial<AttestationPayload> = {}): AttestationPayload {
  return createAttestation({
    assetClass: "invoice",
    assetId: keccak256(stringToHex(`invoice-${Math.random()}`)),
    underwriter: testAccount.address,
    subject: ZERO_ADDRESS,
    riskScore: 742,
    riskTier: "BBB",
    issuedAt: 1_800_000_000,
    expiresAt: 1_831_536_000,
    nonce: 1n,
    supportingData: [],
    ...overrides,
  });
}

describe("verifyAttestationBatch", () => {
  it("verifies an all-valid batch and reports aggregate stats", async () => {
    const items: BatchAttestationItem[] = [];
    for (let i = 0; i < 3; i++) {
      const payload = samplePayload({ nonce: BigInt(i + 1) });
      const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);
      items.push({ payload, signature, domain });
    }

    const { results, stats } = await verifyAttestationBatch(items);

    expect(results).toHaveLength(3);
    expect(results.every((r) => r.valid)).toBe(true);
    expect(stats).toEqual({ total: 3, valid: 3, invalid: 0, expired: 0 });
  });

  it("preserves input order and index in a mixed valid/invalid/expired batch", async () => {
    const validPayload = samplePayload({ nonce: 1n });
    const validSig = await signAttestation(validPayload, domain, TEST_PRIVATE_KEY);

    const wrongSignerPayload = samplePayload({ nonce: 2n });
    const wrongSig = await signAttestation(wrongSignerPayload, domain, OTHER_PRIVATE_KEY);

    const expiredPayload = samplePayload({ nonce: 3n, expiresAt: 1_000 });
    const expiredSig = await signAttestation(expiredPayload, domain, TEST_PRIVATE_KEY);

    const items: BatchAttestationItem[] = [
      { payload: validPayload, signature: validSig, domain },
      { payload: wrongSignerPayload, signature: wrongSig, domain },
      { payload: expiredPayload, signature: expiredSig, domain, options: { now: 2_000 } },
    ];

    const { results, stats } = await verifyAttestationBatch(items);

    expect(results.map((r) => r.index)).toEqual([0, 1, 2]);
    expect(results[0]!.valid).toBe(true);
    expect(results[1]!.valid).toBe(false);
    expect(results[1]!.signer?.toLowerCase()).toBe(otherAccount.address.toLowerCase());
    expect(results[2]!.valid).toBe(false);
    expect(results[2]!.reason).toMatch(/expired/);

    expect(stats).toEqual({ total: 3, valid: 1, invalid: 2, expired: 1 });
  });

  it("returns empty results/zeroed stats for an empty batch", async () => {
    const { results, stats } = await verifyAttestationBatch([]);
    expect(results).toEqual([]);
    expect(stats).toEqual({ total: 0, valid: 0, invalid: 0, expired: 0 });
  });

  it("verifies items concurrently — a bad signature on one item doesn't affect others", async () => {
    const okPayload = samplePayload({ nonce: 10n });
    const okSig = await signAttestation(okPayload, domain, TEST_PRIVATE_KEY);

    const items: BatchAttestationItem[] = [
      { payload: okPayload, signature: okSig, domain },
      { payload: samplePayload({ nonce: 11n }), signature: "0xdeadbeef", domain },
    ];

    const { results, stats } = await verifyAttestationBatch(items);
    expect(results[0]!.valid).toBe(true);
    expect(results[1]!.valid).toBe(false);
    expect(stats.valid).toBe(1);
    expect(stats.invalid).toBe(1);
  });
});
