import { decodeAbiParameters, encodeAbiParameters, parseAbiParameters } from "viem";
import type { Hex } from "viem";
import type { AttestationPayload, EncodedAttestation } from "./types.js";
import { hashSupportingData } from "./eip712.js";
import { ZERO_BYTES32 } from "./constants.js";

/**
 * ABI tuple layout for the compact, on-chain-ready form of an attestation.
 * Mirrors `ATTESTATION_EIP712_TYPES` field-for-field (including collapsing
 * `supportingData` into `supportingDataHash`) so the encoded bytes are a
 * faithful compact serialization of what was actually signed.
 */
const ENCODED_ATTESTATION_ABI = parseAbiParameters(
  "(uint16 schemaVersion, string assetClass, bytes32 assetId, address underwriter, address subject, uint16 riskScore, string riskTier, uint64 issuedAt, uint64 expiresAt, uint256 nonce, bytes32 supportingDataHash, bytes32 supersedes) att",
);

/**
 * ABI-encode an attestation into the compact form a smart contract would
 * store or emit. `supportingData` is committed to via `supportingDataHash`
 * rather than encoded in full (same tradeoff as the EIP-712 struct — see
 * `eip712.ts`).
 */
export function encodeAttestation(payload: AttestationPayload): Hex {
  const supportingDataHash = hashSupportingData(payload.supportingData);
  return encodeAbiParameters(ENCODED_ATTESTATION_ABI, [
    {
      schemaVersion: payload.schemaVersion,
      assetClass: payload.assetClass,
      assetId: payload.assetId,
      underwriter: payload.underwriter,
      subject: payload.subject,
      riskScore: payload.riskScore,
      riskTier: payload.riskTier,
      issuedAt: BigInt(payload.issuedAt),
      expiresAt: BigInt(payload.expiresAt),
      nonce: payload.nonce,
      supportingDataHash,
      supersedes: payload.supersedes ?? ZERO_BYTES32,
    },
  ]);
}

/**
 * Decode bytes produced by `encodeAttestation` back into an `EncodedAttestation`.
 * Note this is lossy relative to the original `AttestationPayload`: the full
 * `supportingData` array is not recoverable from the encoded bytes, only its
 * `supportingDataHash` commitment (by design — that's the whole point of
 * committing to a hash instead of embedding the array on-chain).
 */
export function decodeAttestation(encoded: Hex): EncodedAttestation {
  const [tuple] = decodeAbiParameters(ENCODED_ATTESTATION_ABI, encoded);
  return {
    schemaVersion: Number(tuple.schemaVersion),
    assetClass: tuple.assetClass,
    assetId: tuple.assetId,
    underwriter: tuple.underwriter,
    subject: tuple.subject,
    riskScore: Number(tuple.riskScore),
    riskTier: tuple.riskTier,
    issuedAt: Number(tuple.issuedAt),
    expiresAt: Number(tuple.expiresAt),
    nonce: BigInt(tuple.nonce),
    supportingDataHash: tuple.supportingDataHash,
    supersedes: tuple.supersedes,
  };
}
