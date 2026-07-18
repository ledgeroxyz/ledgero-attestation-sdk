import { encodeAbiParameters, keccak256, parseAbiParameters } from "viem";
import type { Address, Hex } from "viem";
import type { AttestationPayload, SupportingDataRef } from "./types.js";
import { ZERO_BYTES32 } from "./constants.js";

/** EIP-712 `primaryType` for a LEDGERO underwriting attestation. */
export const ATTESTATION_PRIMARY_TYPE = "UnderwritingAttestation" as const;

/**
 * EIP-712 type definition for `UnderwritingAttestation`. `supportingData`
 * (a dynamic array of structs) is intentionally NOT part of this struct —
 * dynamic arrays make typed-data structs unwieldy and gas-expensive to
 * verify on-chain. Instead it's committed to as `supportingDataHash`, a
 * single `bytes32` produced by `hashSupportingData`. Verifiers who need the
 * full list must fetch it out-of-band (e.g. from the URI the attestation was
 * published alongside) and recompute the hash to check it matches.
 */
export const ATTESTATION_EIP712_TYPES = {
  UnderwritingAttestation: [
    { name: "schemaVersion", type: "uint16" },
    { name: "assetClass", type: "string" },
    { name: "assetId", type: "bytes32" },
    { name: "underwriter", type: "address" },
    { name: "subject", type: "address" },
    { name: "riskScore", type: "uint16" },
    { name: "riskTier", type: "string" },
    { name: "issuedAt", type: "uint64" },
    { name: "expiresAt", type: "uint64" },
    { name: "nonce", type: "uint256" },
    { name: "supportingDataHash", type: "bytes32" },
    { name: "supersedes", type: "bytes32" },
  ],
} as const;

const SUPPORTING_DATA_ABI = parseAbiParameters("(string label, string uri, bytes32 hash)[] refs");

/**
 * Deterministic commitment to a `SupportingDataRef[]` array: ABI-encodes the
 * array (as a tuple array, preserving order) and keccak256-hashes the
 * result. Order-sensitive by design — reordering supporting docs changes the
 * hash, which is the conservative choice for an underwriting record. Returns
 * `ZERO_BYTES32` for an empty array.
 */
export function hashSupportingData(refs: readonly SupportingDataRef[]): Hex {
  if (refs.length === 0) return ZERO_BYTES32;
  const encoded = encodeAbiParameters(SUPPORTING_DATA_ABI, [
    refs.map((r) => ({ label: r.label, uri: r.uri, hash: r.hash })),
  ]);
  return keccak256(encoded);
}

/** The EIP-712 `message` object for an attestation payload, ready to pass to viem's typed-data helpers. */
export interface AttestationTypedMessage {
  schemaVersion: number;
  assetClass: string;
  assetId: Hex;
  underwriter: Address;
  subject: Address;
  riskScore: number;
  riskTier: string;
  issuedAt: bigint;
  expiresAt: bigint;
  nonce: bigint;
  supportingDataHash: Hex;
  supersedes: Hex;
}

/** Project an `AttestationPayload` down to the EIP-712 `message` shape (collapsing `supportingData` into its hash). */
export function toAttestationMessage(payload: AttestationPayload): AttestationTypedMessage {
  return {
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
    supportingDataHash: hashSupportingData(payload.supportingData),
    supersedes: payload.supersedes ?? ZERO_BYTES32,
  };
}
