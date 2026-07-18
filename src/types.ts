import type { Address, Hex } from "viem";

/**
 * Current schema version emitted by this SDK. Bump this whenever the
 * `UnderwritingAttestation` field layout (and therefore the EIP-712 struct /
 * ABI-encoded on-chain form) changes in a way that isn't backwards compatible.
 *
 * Consumers should always check `payload.schemaVersion` before trusting the
 * shape of a decoded/received attestation — this library does not silently
 * migrate old versions.
 */
export const ATTESTATION_SCHEMA_VERSION = 1;

/**
 * Broad asset classes LEDGERO underwrites. `"other"` is an intentional
 * escape hatch for asset types not yet formalized — treat it as
 * lower-confidence by convention.
 */
export type AssetClass = "invoice" | "receivable" | "real_estate" | "inventory" | "other";

/**
 * Risk tier label attached to an attestation. This vocabulary is chosen to be
 * conceptually compatible with the `tier` field on `ScoreResult` as produced
 * by `@ledgeroxyz/risk-sdk` (LEDGERO's structured risk-assessment package) —
 * this package does NOT import or depend on risk-sdk, it only agrees on the
 * string vocabulary so a `ScoreResult.tier` can be dropped in directly.
 */
export type RiskTier = "AAA" | "AA" | "A" | "BBB" | "BB" | "B" | "CCC" | "CC" | "C" | "D";

/**
 * A reference to an off-chain source document backing an attestation
 * (an invoice PDF, a KYC report, an appraisal, an OCR extraction artifact,
 * etc). `hash` should be a keccak256 (or other agreed) content hash of the
 * document so the reference is tamper-evident even though the document
 * itself lives off-chain.
 */
export interface SupportingDataRef {
  /** Human-readable label, e.g. "invoice-pdf", "kyc-report", "appraisal-2026". */
  label: string;
  /** URI pointing to the source document (ipfs://, ar://, https://, etc). */
  uri: string;
  /** 0x-prefixed 32-byte content hash of the document. */
  hash: Hex;
}

/**
 * The canonical LEDGERO underwriting attestation payload. This is the
 * "logical" record — the full data a verifier or downstream consumer cares
 * about. For signing (EIP-712) and on-chain storage, `supportingData` is
 * committed to as a single `bytes32` hash (see `hashSupportingData`) rather
 * than being embedded field-by-field, since it's a dynamic-length array.
 */
export interface AttestationPayload {
  /** Schema/version tag for this payload's field layout. See `ATTESTATION_SCHEMA_VERSION`. */
  schemaVersion: number;
  /** The class of real-world asset being underwritten. */
  assetClass: AssetClass;
  /** Unique identifier for the asset (e.g. keccak256 of an internal asset ID, or a bytes32 UUID). */
  assetId: Hex;
  /** Address of the underwriting agent (LEDGERO AI agent instance / operator key) that produced this attestation. */
  underwriter: Address;
  /** Address of the asset issuer/owner this attestation concerns. Use the zero address if not applicable. */
  subject: Address;
  /**
   * Risk score, integer in the 0-1000 range (i.e. basis-point-style
   * precision on a 0-100 scale) to avoid floating point in signed/on-chain
   * data. Conceptually compatible with `ScoreResult.score` from risk-sdk —
   * multiply a 0-100 float score by 10 when constructing this field.
   */
  riskScore: number;
  /** Categorical risk tier. See `RiskTier`. */
  riskTier: RiskTier;
  /** Unix timestamp (seconds) the attestation was issued. */
  issuedAt: number;
  /** Unix timestamp (seconds) the attestation expires. `0` means "does not expire". */
  expiresAt: number;
  /** Replay-protection / uniqueness nonce, scoped to `underwriter`. */
  nonce: bigint;
  /** Off-chain source documents this attestation is based on. */
  supportingData: SupportingDataRef[];
}

/** Convenience constructor input: `schemaVersion` defaults to the current schema version if omitted. */
export type NewAttestationInput = Omit<AttestationPayload, "schemaVersion"> & {
  schemaVersion?: number;
};

/**
 * Build an `AttestationPayload`, defaulting `schemaVersion` to the SDK's
 * current `ATTESTATION_SCHEMA_VERSION`. Purely a typed convenience — the
 * result is a plain object, no validation is performed here (see individual
 * helpers, which will throw on structurally invalid input where relevant).
 */
export function createAttestation(input: NewAttestationInput): AttestationPayload {
  return {
    schemaVersion: input.schemaVersion ?? ATTESTATION_SCHEMA_VERSION,
    assetClass: input.assetClass,
    assetId: input.assetId,
    underwriter: input.underwriter,
    subject: input.subject,
    riskScore: input.riskScore,
    riskTier: input.riskTier,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
    supportingData: input.supportingData,
  };
}

/** EIP-712 domain parameters an attestation is signed/verified under. */
export interface AttestationDomain {
  /** Human-readable domain name, e.g. "LEDGERO Underwriting Attestation". */
  name: string;
  /** Domain version string, e.g. "1". */
  version: string;
  /** Chain ID the signature is scoped to. */
  chainId: number;
  /** Address of the verifying contract (use the intended consumer contract, or a well-known placeholder if off-chain only). */
  verifyingContract: Address;
}

/** The compact, on-chain-ready encoded form of an attestation (see `encodeAttestation` / `decodeAttestation`). */
export interface EncodedAttestation {
  schemaVersion: number;
  assetClass: string;
  assetId: Hex;
  underwriter: Address;
  subject: Address;
  riskScore: number;
  riskTier: string;
  issuedAt: number;
  expiresAt: number;
  nonce: bigint;
  /** keccak256 commitment to the full `supportingData` array — see `hashSupportingData`. */
  supportingDataHash: Hex;
}
