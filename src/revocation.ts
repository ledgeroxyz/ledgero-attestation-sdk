import type { Hex } from "viem";
import type { AttestationDomain, AttestationPayload } from "./types.js";
import { hashAttestation } from "./hash.js";
import { verifyAttestation, type VerifyAttestationOptions, type VerifyAttestationResult } from "./verify.js";

/** A single revocation record. */
export interface RevocationRecord {
  /** The `hashAttestation` content hash of the revoked attestation. */
  attestationHash: Hex;
  /** Optional human-readable reason (e.g. "superseded", "issuer error", "fraud"). */
  reason?: string;
  /** Unix timestamp (seconds) the revocation was recorded. */
  revokedAt: number;
}

/**
 * Pluggable storage backend for a `RevocationRegistry`. The default,
 * `InMemoryRevocationStore`, is process-local and non-persistent — swap in
 * an implementation backed by a database, KV store, or on-chain registry
 * for production use by implementing this interface (mirrors the
 * store-interface pattern used by x402-toolkit's `SpendTracker`).
 */
export interface RevocationStore {
  get(attestationHash: Hex): RevocationRecord | undefined;
  set(attestationHash: Hex, record: RevocationRecord): void;
  delete(attestationHash: Hex): boolean;
  values(): IterableIterator<RevocationRecord>;
}

/** Default in-memory `RevocationStore`, backed by a `Map`. Not persisted across process restarts. */
export class InMemoryRevocationStore implements RevocationStore {
  private readonly records = new Map<Hex, RevocationRecord>();

  get(attestationHash: Hex): RevocationRecord | undefined {
    return this.records.get(attestationHash);
  }

  set(attestationHash: Hex, record: RevocationRecord): void {
    this.records.set(attestationHash, record);
  }

  delete(attestationHash: Hex): boolean {
    return this.records.delete(attestationHash);
  }

  values(): IterableIterator<RevocationRecord> {
    return this.records.values();
  }
}

/**
 * Tracks revoked attestations by content hash (see `hashAttestation`), so a
 * verifier can reject an attestation whose signature is still
 * cryptographically valid but which has since been withdrawn (e.g. the
 * underlying asset was mis-assessed, the underwriter made an error, or the
 * attestation was superseded/amended — see `chain.ts`).
 *
 * Backed by a pluggable `RevocationStore` (defaults to an in-memory `Map`);
 * pass a custom store to persist revocations elsewhere.
 */
export class RevocationRegistry {
  private readonly store: RevocationStore;

  constructor(store: RevocationStore = new InMemoryRevocationStore()) {
    this.store = store;
  }

  /** Mark an attestation (by its content hash) as revoked. Overwrites any existing record for that hash. */
  revoke(attestationHash: Hex, reason?: string, revokedAt: number = Math.floor(Date.now() / 1000)): void {
    this.store.set(attestationHash, { attestationHash, reason, revokedAt });
  }

  /** Remove a revocation record, if present. Returns whether a record was actually removed. */
  unrevoke(attestationHash: Hex): boolean {
    return this.store.delete(attestationHash);
  }

  /** Whether the given attestation hash is currently revoked. */
  isRevoked(attestationHash: Hex): boolean {
    return this.store.get(attestationHash) !== undefined;
  }

  /** Look up the revocation record for an attestation hash, if any. */
  getRevocation(attestationHash: Hex): RevocationRecord | undefined {
    return this.store.get(attestationHash);
  }

  /** List all currently-revoked records. */
  listRevoked(): RevocationRecord[] {
    return Array.from(this.store.values());
  }
}

export interface VerifyAttestationWithRevocationResult extends VerifyAttestationResult {
  /** The content hash (`hashAttestation`) this check was run against. */
  attestationHash: Hex;
  /** Whether this attestation hash is present in the revocation registry. */
  revoked: boolean;
  /** The matching revocation record, if `revoked` is `true`. */
  revocation?: RevocationRecord;
}

/**
 * Convenience helper composing `verifyAttestation` with a
 * `RevocationRegistry` check: an attestation is only considered `valid` if
 * the signature verifies AND it has not been revoked. Signature/expiry
 * failures are reported the same way `verifyAttestation` reports them;
 * revocation is checked independently and always reported via `revoked` /
 * `revocation`, even when the signature itself is invalid.
 */
export async function verifyAttestationWithRevocation(
  payload: AttestationPayload,
  domain: AttestationDomain,
  signature: Hex,
  registry: RevocationRegistry,
  options: VerifyAttestationOptions = {},
): Promise<VerifyAttestationWithRevocationResult> {
  const attestationHash = hashAttestation(payload);
  const revocation = registry.getRevocation(attestationHash);
  const revoked = revocation !== undefined;

  const base = await verifyAttestation(payload, domain, signature, options);

  if (!base.valid) {
    return { ...base, attestationHash, revoked, revocation };
  }

  if (revoked) {
    return {
      valid: false,
      signer: base.signer,
      reason: `attestation revoked${revocation?.reason ? `: ${revocation.reason}` : ""}`,
      attestationHash,
      revoked,
      revocation,
    };
  }

  return { ...base, attestationHash, revoked: false };
}
