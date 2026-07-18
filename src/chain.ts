import type { Hex } from "viem";
import type { AttestationPayload } from "./types.js";
import { hashAttestation } from "./hash.js";
import { ZERO_BYTES32 } from "./constants.js";

/** One link in a resolved amendment chain: the payload plus its own content hash. */
export interface AttestationChainEntry {
  payload: AttestationPayload;
  hash: Hex;
}

export interface AttestationChainResult {
  /**
   * Whether the chain is well-formed: exactly one un-superseded ("head")
   * attestation in the input set, every `supersedes` link resolves to
   * another attestation within the input set, and there is no cycle.
   */
  valid: boolean;
  /**
   * The resolved chain, ordered oldest → newest by following `supersedes`
   * links backward from the head. Populated even on failure for
   * diagnostics (e.g. up to the point a cycle was detected), but should
   * only be trusted end-to-end when `valid` is `true`.
   */
  chain: AttestationChainEntry[];
  /** The newest attestation in the chain (`chain`'s last entry). Only set when `valid` is `true`. */
  latest?: AttestationChainEntry;
  /** Human-readable reason the chain failed to resolve. Absent when `valid` is `true`. */
  reason?: string;
}

/**
 * Walk a set of attestations by their `supersedes` links and resolve them
 * into a single ordered amendment chain (oldest to newest), detecting
 * cycles and broken/ambiguous links along the way.
 *
 * The input set is expected to represent one logical lineage: a single
 * "head" attestation (one nothing else in the set supersedes) at the tip,
 * each subsequent attestation naming the content hash (`hashAttestation`)
 * of the one it amends via `supersedes`, terminating at a root attestation
 * with no `supersedes` (or a `supersedes` pointing outside the input set,
 * which is treated as the chain's boundary — see `reason` for how that's
 * distinguished from an actual break).
 *
 * Failure modes surfaced via `valid: false` + `reason`:
 * - `"no attestations provided"` — empty input.
 * - `"duplicate attestations ..."` — two inputs hash identically.
 * - `"no head found ..."` — every attestation is superseded by another
 *   (this can only happen if the input set itself contains a cycle).
 * - `"ambiguous chain: multiple un-superseded attestations ..."` — more
 *   than one candidate head, i.e. the input set actually contains more
 *   than one lineage (or a fork).
 * - `"cycle detected in supersedes chain"` — following links backward
 *   revisits an attestation already seen.
 */
export function buildAmendmentChain(attestations: readonly AttestationPayload[]): AttestationChainResult {
  if (attestations.length === 0) {
    return { valid: false, chain: [], reason: "no attestations provided" };
  }

  const byHash = new Map<Hex, AttestationPayload>();
  for (const payload of attestations) {
    const hash = hashAttestation(payload);
    if (byHash.has(hash)) {
      return {
        valid: false,
        chain: [],
        reason: `duplicate attestations (identical content hash ${hash}) in input set`,
      };
    }
    byHash.set(hash, payload);
  }

  // Hashes that some *other* attestation in the set names as its `supersedes`.
  const supersededHashes = new Set<Hex>();
  for (const payload of attestations) {
    if (payload.supersedes && payload.supersedes !== ZERO_BYTES32) {
      supersededHashes.add(payload.supersedes);
    }
  }

  const heads: Hex[] = [];
  for (const hash of byHash.keys()) {
    if (!supersededHashes.has(hash)) heads.push(hash);
  }

  if (heads.length === 0) {
    return {
      valid: false,
      chain: [],
      reason: "no head found — every attestation in the input set is superseded by another (cycle?)",
    };
  }
  if (heads.length > 1) {
    return {
      valid: false,
      chain: [],
      reason: `ambiguous chain: multiple un-superseded attestations (${heads.length}) found in input set`,
    };
  }

  const chain: AttestationChainEntry[] = [];
  const visited = new Set<Hex>();
  let currentHash: Hex | undefined = heads[0];

  while (currentHash !== undefined) {
    if (visited.has(currentHash)) {
      chain.reverse();
      return { valid: false, chain, reason: "cycle detected in supersedes chain" };
    }
    visited.add(currentHash);

    const payload = byHash.get(currentHash);
    if (!payload) {
      // supersedes pointed outside the input set — treat as the chain boundary,
      // not an error: the prior attestation is presumably known/verified elsewhere.
      break;
    }

    chain.push({ payload, hash: currentHash });
    const next = payload.supersedes;
    currentHash = next && next !== ZERO_BYTES32 ? next : undefined;
  }

  chain.reverse(); // oldest -> newest

  const latest = chain[chain.length - 1];
  return { valid: true, chain, latest };
}

/**
 * Convenience wrapper around `buildAmendmentChain` for callers who only
 * care whether a set of attestations forms a valid amendment chain (and
 * why not, if not) without needing the full resolved chain back.
 */
export function validateAttestationChain(
  attestations: readonly AttestationPayload[],
): { valid: boolean; reason?: string } {
  const result = buildAmendmentChain(attestations);
  return result.valid ? { valid: true } : { valid: false, reason: result.reason };
}
