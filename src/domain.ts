import type { Address } from "viem";
import type { AttestationDomain } from "./types.js";

/** Default EIP-712 domain name, if the caller doesn't supply one. */
export const DEFAULT_DOMAIN_NAME = "LEDGERO Underwriting Attestation";

/** Default EIP-712 domain version, if the caller doesn't supply one. */
export const DEFAULT_DOMAIN_VERSION = "1";

/**
 * Build an `AttestationDomain`. `chainId` and `verifyingContract` are
 * required — they're what actually scope a signature to a specific
 * deployment, and getting them wrong silently produces signatures that
 * verify fine in tests but not against the intended on-chain verifier.
 */
export function createAttestationDomain(params: {
  chainId: number;
  verifyingContract: Address;
  name?: string;
  version?: string;
}): AttestationDomain {
  return {
    name: params.name ?? DEFAULT_DOMAIN_NAME,
    version: params.version ?? DEFAULT_DOMAIN_VERSION,
    chainId: params.chainId,
    verifyingContract: params.verifyingContract,
  };
}

/** Shape viem's typed-data functions (`hashTypedData`, `signTypedData`, `recoverTypedDataAddress`) expect for `domain`. */
export function toViemDomain(domain: AttestationDomain) {
  return {
    name: domain.name,
    version: domain.version,
    chainId: domain.chainId,
    verifyingContract: domain.verifyingContract,
  } as const;
}
