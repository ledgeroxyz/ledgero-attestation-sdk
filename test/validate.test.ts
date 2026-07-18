import { describe, expect, it } from "vitest";
import { keccak256, stringToHex } from "viem";
import {
  ATTESTATION_SCHEMA_VERSION,
  createAttestation,
  hashAttestation,
  validateAttestationPayload,
  ZERO_ADDRESS,
} from "../src/index.js";

const UNDERWRITER = "0x1111111111111111111111111111111111111111";

function validPayloadJson() {
  const payload = createAttestation({
    assetClass: "invoice",
    assetId: keccak256(stringToHex("invoice-INV-2026-0042")),
    underwriter: UNDERWRITER,
    subject: ZERO_ADDRESS,
    riskScore: 742,
    riskTier: "BBB",
    issuedAt: 1_800_000_000,
    expiresAt: 1_831_536_000,
    nonce: 1n,
    supportingData: [
      { label: "invoice-pdf", uri: "ipfs://bafybe.../invoice.pdf", hash: keccak256(stringToHex("bytes")) },
    ],
  });
  return payload;
}

describe("validateAttestationPayload", () => {
  it("accepts a well-formed payload built via createAttestation", () => {
    const payload = validPayloadJson();
    const result = validateAttestationPayload(payload);
    expect(result).toEqual({ valid: true, errors: [] });
  });

  it("accepts a well-formed payload with an optional supersedes field set", () => {
    const prior = validPayloadJson();
    const payload = { ...validPayloadJson(), supersedes: hashAttestation(prior) };
    const result = validateAttestationPayload(payload);
    expect(result).toEqual({ valid: true, errors: [] });
  });

  it("accepts a payload with an empty supportingData array", () => {
    const payload = { ...validPayloadJson(), supportingData: [] };
    expect(validateAttestationPayload(payload).valid).toBe(true);
  });

  it("rejects a completely non-object value", () => {
    expect(validateAttestationPayload(null).valid).toBe(false);
    expect(validateAttestationPayload("not a payload").valid).toBe(false);
    expect(validateAttestationPayload(42).valid).toBe(false);
    expect(validateAttestationPayload([]).valid).toBe(false);
  });

  it("rejects a payload missing a required field, naming the missing field", () => {
    const { underwriter: _underwriter, ...rest } = validPayloadJson();
    const result = validateAttestationPayload(rest);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.startsWith("underwriter:"))).toBe(true);
  });

  it("rejects an invalid assetClass enum value", () => {
    const payload = { ...validPayloadJson(), assetClass: "cryptocurrency" };
    const result = validateAttestationPayload(payload);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.startsWith("assetClass:"))).toBe(true);
  });

  it("rejects an invalid riskTier enum value", () => {
    const payload = { ...validPayloadJson(), riskTier: "F" };
    const result = validateAttestationPayload(payload);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.startsWith("riskTier:"))).toBe(true);
  });

  it("rejects riskScore outside the 0-1000 range", () => {
    expect(validateAttestationPayload({ ...validPayloadJson(), riskScore: -1 }).valid).toBe(false);
    expect(validateAttestationPayload({ ...validPayloadJson(), riskScore: 1001 }).valid).toBe(false);
  });

  it("rejects a malformed assetId (not a 0x-prefixed 32-byte hex string)", () => {
    const result = validateAttestationPayload({ ...validPayloadJson(), assetId: "0xnothex" });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.startsWith("assetId:"))).toBe(true);
  });

  it("rejects a malformed underwriter address", () => {
    const result = validateAttestationPayload({ ...validPayloadJson(), underwriter: "not-an-address" });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.startsWith("underwriter:"))).toBe(true);
  });

  it("rejects a non-bigint nonce (e.g. a JSON-deserialized number or string)", () => {
    expect(validateAttestationPayload({ ...validPayloadJson(), nonce: 1 }).valid).toBe(false);
    expect(validateAttestationPayload({ ...validPayloadJson(), nonce: "1" }).valid).toBe(false);
  });

  it("rejects a negative nonce", () => {
    const result = validateAttestationPayload({ ...validPayloadJson(), nonce: -1n });
    expect(result.valid).toBe(false);
  });

  it("rejects a supportingData entry with a malformed hash, reporting a path into the array", () => {
    const payload = {
      ...validPayloadJson(),
      supportingData: [{ label: "bad", uri: "ipfs://x", hash: "0xzz" }],
    };
    const result = validateAttestationPayload(payload);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.startsWith("supportingData.0.hash:"))).toBe(true);
  });

  it("rejects a supportingData entry missing its label", () => {
    const payload = {
      ...validPayloadJson(),
      supportingData: [{ uri: "ipfs://x", hash: keccak256(stringToHex("x")) }],
    };
    const result = validateAttestationPayload(payload);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.startsWith("supportingData.0.label:"))).toBe(true);
  });

  it("rejects a malformed supersedes field when provided", () => {
    const result = validateAttestationPayload({ ...validPayloadJson(), supersedes: "0xdead" });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.startsWith("supersedes:"))).toBe(true);
  });

  it("collects multiple errors at once for a badly malformed payload", () => {
    const result = validateAttestationPayload({
      schemaVersion: ATTESTATION_SCHEMA_VERSION,
      assetClass: "bogus",
      riskScore: 9999,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(1);
  });
});
