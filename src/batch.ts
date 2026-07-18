import type { Hex } from "viem";
import type { AttestationDomain, AttestationPayload } from "./types.js";
import { verifyAttestation, type VerifyAttestationOptions, type VerifyAttestationResult } from "./verify.js";

/** A single attestation to verify as part of a batch. */
export interface BatchAttestationItem {
  payload: AttestationPayload;
  signature: Hex;
  domain: AttestationDomain;
  /** Per-item verification options (e.g. a different `expectedSigner` per item). */
  options?: VerifyAttestationOptions;
}

/** Per-item outcome, carrying the original index so callers can map results back to their input array. */
export interface BatchVerificationItemResult extends VerifyAttestationResult {
  /** Index of this item in the input `items` array. */
  index: number;
}

/** Aggregate counts across a batch verification run. */
export interface BatchVerificationStats {
  /** Total number of items verified. */
  total: number;
  /** Number of items that verified successfully. */
  valid: number;
  /** Number of items that failed verification for any reason (including expiry). */
  invalid: number;
  /** Subset of `invalid` whose failure reason was specifically expiry. */
  expired: number;
}

export interface BatchVerificationResult {
  /** Per-item results, in the same order as the input `items` array. */
  results: BatchVerificationItemResult[];
  stats: BatchVerificationStats;
}

/**
 * Verify many attestations concurrently. Each item is verified independently
 * via `verifyAttestation` (so a malformed/tampered item can't affect the
 * others), and results are returned in the same order as the input.
 *
 * Useful for bulk ingestion/audit flows — e.g. checking a batch of
 * attestations fetched from storage or received over the network before
 * trusting any of them.
 */
export async function verifyAttestationBatch(
  items: readonly BatchAttestationItem[],
): Promise<BatchVerificationResult> {
  const settled = await Promise.all(
    items.map(async (item, index): Promise<BatchVerificationItemResult> => {
      const result = await verifyAttestation(item.payload, item.domain, item.signature, item.options);
      return { ...result, index };
    }),
  );

  const stats: BatchVerificationStats = {
    total: settled.length,
    valid: 0,
    invalid: 0,
    expired: 0,
  };

  for (const result of settled) {
    if (result.valid) {
      stats.valid += 1;
    } else {
      stats.invalid += 1;
      if (result.reason === "attestation expired") {
        stats.expired += 1;
      }
    }
  }

  return { results: settled, stats };
}
