import { keccak256 } from "viem";
import type { Hex } from "viem";
import type { AttestationPayload } from "./types.js";
import { encodeAttestation } from "./encode.js";

/**
 * Deterministic, domain-independent content hash of an attestation payload.
 * Two payloads with identical field values (including `supportingData`,
 * via its `supportingDataHash` commitment) always hash to the same value —
 * suitable for content-addressing, deduplication, or as an on-chain
 * reference key.
 *
 * This is intentionally distinct from the EIP-712 signing hash (see
 * `sign.ts` / `hashTypedData`), which additionally binds a domain separator
 * (chain ID, verifying contract, domain name/version). `hashAttestation`
 * answers "what is this attestation's content?"; the EIP-712 hash answers
 * "what, specifically, did this signer sign, in this context?".
 */
export function hashAttestation(payload: AttestationPayload): Hex {
  return keccak256(encodeAttestation(payload));
}
