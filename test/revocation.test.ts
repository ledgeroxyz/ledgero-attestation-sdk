import { describe, expect, it } from "vitest";
import { keccak256, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  createAttestation,
  createAttestationDomain,
  hashAttestation,
  InMemoryRevocationStore,
  RevocationRegistry,
  signAttestation,
  verifyAttestationWithRevocation,
  ZERO_ADDRESS,
  type AttestationPayload,
  type RevocationRecord,
  type RevocationStore,
} from "../src/index.js";

const TEST_PRIVATE_KEY = "0x4dc3172729ffb3af5a2c5454cbed3b658b274a2ed0be0d898602d81f542fa7ab" as const;
const testAccount = privateKeyToAccount(TEST_PRIVATE_KEY);

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

describe("RevocationRegistry", () => {
  it("starts empty", () => {
    const registry = new RevocationRegistry();
    expect(registry.listRevoked()).toEqual([]);
    expect(registry.isRevoked("0xabc")).toBe(false);
  });

  it("revoke/isRevoked/listRevoked round-trip, with optional reason", () => {
    const registry = new RevocationRegistry();
    const payload = samplePayload();
    const hash = hashAttestation(payload);

    expect(registry.isRevoked(hash)).toBe(false);

    registry.revoke(hash, "issuer error");

    expect(registry.isRevoked(hash)).toBe(true);
    const record = registry.getRevocation(hash);
    expect(record?.reason).toBe("issuer error");
    expect(record?.attestationHash).toBe(hash);
    expect(typeof record?.revokedAt).toBe("number");

    const listed = registry.listRevoked();
    expect(listed).toHaveLength(1);
    expect(listed[0]!.attestationHash).toBe(hash);
  });

  it("revoke without a reason is allowed", () => {
    const registry = new RevocationRegistry();
    const hash = hashAttestation(samplePayload());
    registry.revoke(hash);
    expect(registry.isRevoked(hash)).toBe(true);
    expect(registry.getRevocation(hash)?.reason).toBeUndefined();
  });

  it("unrevoke removes a record and reports whether it existed", () => {
    const registry = new RevocationRegistry();
    const hash = hashAttestation(samplePayload());

    expect(registry.unrevoke(hash)).toBe(false);

    registry.revoke(hash, "test");
    expect(registry.unrevoke(hash)).toBe(true);
    expect(registry.isRevoked(hash)).toBe(false);
  });

  it("accepts a pluggable custom store", () => {
    const backing = new Map<string, RevocationRecord>();
    const customStore: RevocationStore = {
      get: (h) => backing.get(h),
      set: (h, r) => {
        backing.set(h, r);
      },
      delete: (h) => backing.delete(h),
      values: () => backing.values(),
    };

    const registry = new RevocationRegistry(customStore);
    const hash = hashAttestation(samplePayload());
    registry.revoke(hash, "via custom store");

    expect(backing.has(hash)).toBe(true);
    expect(registry.isRevoked(hash)).toBe(true);
  });

  it("InMemoryRevocationStore behaves correctly when used directly", () => {
    const store = new InMemoryRevocationStore();
    const hash = hashAttestation(samplePayload());
    expect(store.get(hash)).toBeUndefined();
    store.set(hash, { attestationHash: hash, revokedAt: 123 });
    expect(store.get(hash)?.revokedAt).toBe(123);
    expect(store.delete(hash)).toBe(true);
    expect(store.delete(hash)).toBe(false);
  });
});

describe("verifyAttestationWithRevocation", () => {
  it("is valid when the signature is good and the attestation is not revoked", async () => {
    const registry = new RevocationRegistry();
    const payload = samplePayload();
    const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);

    const result = await verifyAttestationWithRevocation(payload, domain, signature, registry);
    expect(result.valid).toBe(true);
    expect(result.revoked).toBe(false);
    expect(result.attestationHash).toBe(hashAttestation(payload));
  });

  it("is invalid when the attestation has been revoked, even with a good signature", async () => {
    const registry = new RevocationRegistry();
    const payload = samplePayload();
    const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);
    const hash = hashAttestation(payload);

    registry.revoke(hash, "superseded");

    const result = await verifyAttestationWithRevocation(payload, domain, signature, registry);
    expect(result.valid).toBe(false);
    expect(result.revoked).toBe(true);
    expect(result.reason).toMatch(/revoked/);
    expect(result.reason).toMatch(/superseded/);
    expect(result.revocation?.reason).toBe("superseded");
  });

  it("still reports the underlying signature failure reason when signature is bad, regardless of revocation", async () => {
    const registry = new RevocationRegistry();
    const payload = samplePayload();

    const result = await verifyAttestationWithRevocation(payload, domain, "0xdeadbeef", registry);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/signature recovery failed/);
    expect(result.revoked).toBe(false);
  });

  it("reports revoked:true alongside a signature failure if both conditions hold", async () => {
    const registry = new RevocationRegistry();
    const payload = samplePayload({ expiresAt: 1_000 });
    const signature = await signAttestation(payload, domain, TEST_PRIVATE_KEY);
    const hash = hashAttestation(payload);
    registry.revoke(hash, "test");

    const result = await verifyAttestationWithRevocation(payload, domain, signature, registry, { now: 2_000 });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/expired/);
    expect(result.revoked).toBe(true);
  });
});
