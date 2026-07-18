import { describe, expect, it } from "vitest";
import { keccak256, stringToHex } from "viem";
import {
  buildAmendmentChain,
  createAttestation,
  hashAttestation,
  validateAttestationChain,
  ZERO_ADDRESS,
  type AttestationPayload,
} from "../src/index.js";

const UNDERWRITER = "0x1111111111111111111111111111111111111111" as const;

function samplePayload(overrides: Partial<AttestationPayload> = {}): AttestationPayload {
  return createAttestation({
    assetClass: "invoice",
    assetId: keccak256(stringToHex(`asset-${Math.random()}`)),
    underwriter: UNDERWRITER,
    subject: ZERO_ADDRESS,
    riskScore: 500,
    riskTier: "BBB",
    issuedAt: 1_800_000_000,
    expiresAt: 0,
    nonce: 1n,
    supportingData: [],
    ...overrides,
  });
}

describe("buildAmendmentChain / validateAttestationChain", () => {
  it("resolves a single root attestation (no supersedes) as a valid 1-element chain", () => {
    const root = samplePayload();
    const result = buildAmendmentChain([root]);

    expect(result.valid).toBe(true);
    expect(result.chain).toHaveLength(1);
    expect(result.latest?.payload).toBe(root);
    expect(validateAttestationChain([root])).toEqual({ valid: true });
  });

  it("resolves a linear chain of amendments oldest -> newest, regardless of input order", () => {
    const root = samplePayload({ nonce: 1n, riskScore: 500 });
    const rootHash = hashAttestation(root);

    const amendment = samplePayload({ nonce: 2n, riskScore: 600, supersedes: rootHash });
    const amendmentHash = hashAttestation(amendment);

    const latest = samplePayload({ nonce: 3n, riskScore: 700, supersedes: amendmentHash });

    // Deliberately out of order in the input array.
    const result = buildAmendmentChain([latest, root, amendment]);

    expect(result.valid).toBe(true);
    expect(result.chain.map((e) => e.payload.riskScore)).toEqual([500, 600, 700]);
    expect(result.latest?.payload.riskScore).toBe(700);
    expect(result.latest?.hash).toBe(hashAttestation(latest));
  });

  it("treats a supersedes reference outside the input set as the chain boundary, not an error", () => {
    const externalRootHash = keccak256(stringToHex("some-attestation-not-in-this-set"));
    const only = samplePayload({ supersedes: externalRootHash });

    const result = buildAmendmentChain([only]);
    expect(result.valid).toBe(true);
    expect(result.chain).toHaveLength(1);
    expect(result.latest?.payload).toBe(only);
  });

  it("rejects an empty input set", () => {
    const result = buildAmendmentChain([]);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/no attestations provided/);
  });

  it("rejects duplicate attestations (identical content hash)", () => {
    const payload = samplePayload();
    const result = buildAmendmentChain([payload, { ...payload }]);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/duplicate attestations/);
  });

  it("rejects an ambiguous set with more than one un-superseded (head) attestation — a fork", () => {
    const root = samplePayload({ nonce: 1n });
    const rootHash = hashAttestation(root);
    const branchA = samplePayload({ nonce: 2n, supersedes: rootHash });
    const branchB = samplePayload({ nonce: 3n, supersedes: rootHash });

    const result = buildAmendmentChain([root, branchA, branchB]);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/ambiguous chain/);
  });

  it("a 3-way fork off the same root is still reported as ambiguous, not silently picking one branch", () => {
    const root = samplePayload({ nonce: 1n });
    const rootHash = hashAttestation(root);
    const branches = [2n, 3n, 4n].map((nonce) => samplePayload({ nonce, supersedes: rootHash }));

    const result = buildAmendmentChain([root, ...branches]);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/ambiguous chain: multiple un-superseded attestations \(3\)/);
  });

  it("validateAttestationChain returns the same valid/reason verdict as buildAmendmentChain without the full chain", () => {
    expect(validateAttestationChain([])).toEqual({
      valid: false,
      reason: "no attestations provided",
    });

    const root = samplePayload();
    expect(validateAttestationChain([root])).toEqual({ valid: true });
  });
});
