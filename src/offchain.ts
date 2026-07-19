import { sha256, stringToBytes } from "viem";

/**
 * Off-chain, signer-free attestation content — the exact field set the
 * LEDGERO dapp commits to when it issues a pre-on-chain attestation.
 *
 * At the dapp's current stage there is no underwriter private key and no
 * EIP-712 signing: an attestation is issued by computing a SHA-256 digest
 * over a canonical JSON serialization of these fields, and storing that
 * digest (`contentHash`) alongside a generated `attestationId`. That digest
 * is a "faithful stand-in for a signed, verifiable record" — it changes if
 * any assessed input changes, so it's tamper-evident even though nothing is
 * posted on-chain yet.
 *
 * The field ORDER here is load-bearing: the content hash is SHA-256 over
 * `JSON.stringify` of these fields in EXACTLY this order —
 * `assetId, name, assetClass, claimedValue, score, rating, issuedAt`.
 * `attestationId` is intentionally NOT part of the hashed content (it's an
 * identifier for the record, not assessed data), matching the dapp.
 *
 * See `hashAttestationContent` for the hashing rule and
 * `toSignedAttestationPayload` (in `upgrade.ts`) for promoting an off-chain
 * attestation to a full EIP-712 signed on-chain `AttestationPayload`.
 */
export interface AttestationContent {
  /** Identifier of the assessed asset (the dapp's `asset_...` id, or any stable string). */
  assetId: string;
  /** Human-readable asset name. */
  name: string;
  /** Asset class label, as produced by the assessment pipeline (free-form string to stay in lockstep with the dapp). */
  assetClass: string;
  /** Claimed value of the asset (numeric, in the asset's currency). */
  claimedValue: number;
  /** Risk score on the dapp's 0-100 scale. */
  score: number;
  /** Categorical rating label, e.g. "A" | "B" | "C" | "D". */
  rating: string;
  /** ISO-8601 timestamp string the attestation was issued at (the dapp uses `new Date().toISOString()`). */
  issuedAt: string;
  /** Optional record identifier. NOT included in the content hash — carried for convenience. */
  attestationId?: string;
}

/**
 * A fully-formed off-chain attestation: the assessed content plus the
 * generated `attestationId` and the computed `contentHash`. This mirrors what
 * the dapp persists (`attestationId` + `attestationHash`) on an assessed
 * asset record.
 */
export interface OffchainAttestation {
  assetId: string;
  name: string;
  assetClass: string;
  claimedValue: number;
  score: number;
  rating: string;
  issuedAt: string;
  /** Generated record identifier (e.g. `att_<uuid>`). */
  attestationId: string;
  /** SHA-256 content hash — see `hashAttestationContent`. Un-prefixed lowercase hex, matching the dapp byte-for-byte. */
  contentHash: string;
}

/**
 * Canonical JSON serialization the content hash is computed over. The fields
 * are emitted in a FIXED order (`assetId, name, assetClass, claimedValue,
 * score, rating, issuedAt`) rather than trusting the input object's key
 * order, so two callers who build the content object with keys in different
 * orders still produce the same hash — and so it matches the dapp exactly,
 * which literally does `JSON.stringify({ assetId, name, assetClass,
 * claimedValue, score, rating, issuedAt })`.
 */
export function canonicalAttestationContent(content: AttestationContent): string {
  return JSON.stringify({
    assetId: content.assetId,
    name: content.name,
    assetClass: content.assetClass,
    claimedValue: content.claimedValue,
    score: content.score,
    rating: content.rating,
    issuedAt: content.issuedAt,
  });
}

/**
 * Compute the SHA-256 content hash of an off-chain attestation, byte-for-byte
 * identical to what the LEDGERO dapp produces (`sha256Hex` over the canonical
 * JSON above).
 *
 * The returned value is **un-prefixed, lowercase hex** (64 chars) to match the
 * dapp's format exactly — the dapp builds its hex by hand from the digest
 * bytes and does NOT add a `0x` prefix. viem's `sha256` returns a 0x-prefixed
 * hex string, so the prefix is stripped here. If you need a `bytes32` for
 * on-chain use, prepend `0x` (SHA-256 is 32 bytes, so `0x<contentHash>` is a
 * valid `bytes32`) — `toSignedAttestationPayload` does exactly this.
 *
 * This is synchronous: viem's `sha256` is a pure, in-process computation
 * (unlike the dapp's `crypto.subtle.digest`, which is async only because the
 * Web Crypto API is Promise-based — the resulting bytes are the same).
 */
export function hashAttestationContent(content: AttestationContent): string {
  const bytes = stringToBytes(canonicalAttestationContent(content));
  // viem's sha256 -> "0x<64 lowercase hex>"; strip "0x" to match the dapp.
  return sha256(bytes).slice(2);
}

/**
 * Recompute the content hash of `content` and compare it against `hash`.
 * Comparison is case-insensitive and tolerant of an optional `0x` prefix on
 * the supplied hash, so it accepts both the dapp's un-prefixed form and a
 * 0x-prefixed `bytes32`-style hash.
 */
export function verifyContentHash(content: AttestationContent, hash: string): boolean {
  const expected = hashAttestationContent(content);
  const normalized = hash.startsWith("0x") || hash.startsWith("0X") ? hash.slice(2) : hash;
  return expected.toLowerCase() === normalized.toLowerCase();
}

/**
 * Generate a record identifier in the dapp's shape: `att_<uuid-without-dashes>`.
 * Uses the global Web Crypto `crypto.randomUUID()` (available in Node >= 20
 * and all modern browsers), matching the dapp's `newId("att")`.
 */
export function newAttestationId(): string {
  return `att_${crypto.randomUUID().replace(/-/g, "")}`;
}

/**
 * Build a complete off-chain attestation from assessed content: attaches a
 * generated `attestationId` (unless one is supplied) and the computed
 * `contentHash`. This is the SDK equivalent of the dapp's issue step in
 * `runAssessment` — same fields, same hash, same shape of stored record.
 *
 * @param content the assessed fields to attest to
 * @param options.attestationId use this id instead of generating one (falls
 *   back to `content.attestationId` if present, then to a fresh generated id)
 */
export function createOffchainAttestation(
  content: AttestationContent,
  options: { attestationId?: string } = {},
): OffchainAttestation {
  const attestationId = options.attestationId ?? content.attestationId ?? newAttestationId();
  return {
    assetId: content.assetId,
    name: content.name,
    assetClass: content.assetClass,
    claimedValue: content.claimedValue,
    score: content.score,
    rating: content.rating,
    issuedAt: content.issuedAt,
    attestationId,
    contentHash: hashAttestationContent(content),
  };
}
