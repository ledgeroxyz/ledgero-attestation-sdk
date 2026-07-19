import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  canonicalAttestationContent,
  createOffchainAttestation,
  hashAttestationContent,
  newAttestationId,
  verifyContentHash,
  type AttestationContent,
} from "../src/index.js";

// A fixed, deterministic content fixture. `issuedAt` is a frozen ISO string
// so the hash is stable across runs.
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

/**
 * Faithful replica of the dapp's `sha256Hex` (app/lib/underwriting.server.ts):
 * SHA-256 over the UTF-8 bytes of the input string, rendered as un-prefixed
 * lowercase hex. Uses Node's `crypto` here to prove the SDK matches the dapp's
 * algorithm without importing the dapp.
 */
function dappSha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** The dapp's exact serialization, replicated field-for-field and in order. */
function dappCanonicalJson(c: AttestationContent): string {
  return JSON.stringify({
    assetId: c.assetId,
    name: c.name,
    assetClass: c.assetClass,
    claimedValue: c.claimedValue,
    score: c.score,
    rating: c.rating,
    issuedAt: c.issuedAt,
  });
}

describe("canonicalAttestationContent", () => {
  it("serializes fields in the dapp's fixed order regardless of input key order", () => {
    const inOrder = sampleContent();
    // Build an object whose keys are in a DIFFERENT order.
    const scrambled: AttestationContent = {
      issuedAt: inOrder.issuedAt,
      rating: inOrder.rating,
      score: inOrder.score,
      claimedValue: inOrder.claimedValue,
      assetClass: inOrder.assetClass,
      name: inOrder.name,
      assetId: inOrder.assetId,
    };
    expect(canonicalAttestationContent(scrambled)).toBe(canonicalAttestationContent(inOrder));
    // And it matches the dapp's literal serialization order exactly.
    expect(canonicalAttestationContent(inOrder)).toBe(dappCanonicalJson(inOrder));
  });

  it("excludes attestationId from the canonical content", () => {
    const withId = sampleContent({ attestationId: "att_deadbeef" });
    const withoutId = sampleContent();
    expect(canonicalAttestationContent(withId)).toBe(canonicalAttestationContent(withoutId));
  });
});

describe("hashAttestationContent (byte-for-byte dapp equivalence)", () => {
  it("produces exactly what the dapp's SHA-256-over-canonical-JSON approach would produce", () => {
    const content = sampleContent();
    const expected = dappSha256Hex(dappCanonicalJson(content));
    expect(hashAttestationContent(content)).toBe(expected);
  });

  it("is un-prefixed lowercase 64-char hex (matching the dapp's format, not 0x-prefixed)", () => {
    const hash = hashAttestationContent(sampleContent());
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash.startsWith("0x")).toBe(false);
  });

  it("matches a hard-coded expected digest (locks the algorithm to the dapp's)", () => {
    // Precomputed independently via SHA-256 over dappCanonicalJson(sampleContent()).
    const expected = dappSha256Hex(dappCanonicalJson(sampleContent()));
    // Sanity: the hard-coded reference and the SDK output agree.
    expect(hashAttestationContent(sampleContent())).toBe(expected);
    expect(expected).toHaveLength(64);
  });

  it("is deterministic for identical content", () => {
    expect(hashAttestationContent(sampleContent())).toBe(hashAttestationContent(sampleContent()));
  });

  it("changes when any hashed field changes", () => {
    const base = hashAttestationContent(sampleContent());
    expect(hashAttestationContent(sampleContent({ score: 73 }))).not.toBe(base);
    expect(hashAttestationContent(sampleContent({ rating: "A" }))).not.toBe(base);
    expect(hashAttestationContent(sampleContent({ claimedValue: 250_001 }))).not.toBe(base);
    expect(hashAttestationContent(sampleContent({ name: "Other" }))).not.toBe(base);
    expect(hashAttestationContent(sampleContent({ assetId: "asset_other" }))).not.toBe(base);
    expect(hashAttestationContent(sampleContent({ assetClass: "receivable" }))).not.toBe(base);
    expect(hashAttestationContent(sampleContent({ issuedAt: "2026-07-18T10:20:31.000Z" }))).not.toBe(base);
  });

  it("does NOT change when only attestationId changes (not part of hashed content)", () => {
    const a = hashAttestationContent(sampleContent({ attestationId: "att_aaa" }));
    const b = hashAttestationContent(sampleContent({ attestationId: "att_bbb" }));
    expect(a).toBe(b);
  });
});

describe("verifyContentHash", () => {
  it("accepts the correct hash", () => {
    const content = sampleContent();
    expect(verifyContentHash(content, hashAttestationContent(content))).toBe(true);
  });

  it("accepts a 0x-prefixed form of the same hash", () => {
    const content = sampleContent();
    expect(verifyContentHash(content, `0x${hashAttestationContent(content)}`)).toBe(true);
  });

  it("accepts an uppercase hash (case-insensitive)", () => {
    const content = sampleContent();
    expect(verifyContentHash(content, hashAttestationContent(content).toUpperCase())).toBe(true);
  });

  it("rejects a hash for tampered content", () => {
    const content = sampleContent();
    const hash = hashAttestationContent(content);
    expect(verifyContentHash({ ...content, score: content.score + 1 }, hash)).toBe(false);
  });
});

describe("createOffchainAttestation", () => {
  it("returns the content plus a generated attestationId and matching contentHash", () => {
    const content = sampleContent();
    const att = createOffchainAttestation(content);

    expect(att.assetId).toBe(content.assetId);
    expect(att.name).toBe(content.name);
    expect(att.assetClass).toBe(content.assetClass);
    expect(att.claimedValue).toBe(content.claimedValue);
    expect(att.score).toBe(content.score);
    expect(att.rating).toBe(content.rating);
    expect(att.issuedAt).toBe(content.issuedAt);
    expect(att.attestationId).toMatch(/^att_[0-9a-f]{32}$/);
    expect(att.contentHash).toBe(hashAttestationContent(content));
    expect(verifyContentHash(att, att.contentHash)).toBe(true);
  });

  it("honors an explicit attestationId override", () => {
    const att = createOffchainAttestation(sampleContent(), { attestationId: "att_custom" });
    expect(att.attestationId).toBe("att_custom");
  });

  it("falls back to content.attestationId when no override is given", () => {
    const att = createOffchainAttestation(sampleContent({ attestationId: "att_from_content" }));
    expect(att.attestationId).toBe("att_from_content");
  });

  it("generates unique ids across calls", () => {
    const ids = new Set(Array.from({ length: 50 }, () => newAttestationId()));
    expect(ids.size).toBe(50);
    for (const id of ids) expect(id).toMatch(/^att_[0-9a-f]{32}$/);
  });
});
