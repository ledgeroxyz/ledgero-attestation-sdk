import { keccak256, stringToHex } from "viem";
import type { Address, Hex } from "viem";
import type {
  AssetClass,
  AttestationPayload,
  RiskTier,
  SupportingDataRef,
} from "./types.js";
import { createAttestation } from "./types.js";
import { ZERO_ADDRESS } from "./constants.js";
import {
  hashAttestationContent,
  type AttestationContent,
  type OffchainAttestation,
} from "./offchain.js";

/** SDK-recognized asset classes, used to decide whether a dapp `assetClass` string maps directly. */
const SDK_ASSET_CLASSES: readonly AssetClass[] = [
  "invoice",
  "receivable",
  "real_estate",
  "inventory",
  "other",
] as const;

/** SDK-recognized risk tiers, used to decide whether a dapp `rating` string maps directly. */
const SDK_RISK_TIERS: readonly RiskTier[] = [
  "AAA",
  "AA",
  "A",
  "BBB",
  "BB",
  "B",
  "CCC",
  "CC",
  "C",
  "D",
] as const;

function isAssetClass(value: string): value is AssetClass {
  return (SDK_ASSET_CLASSES as readonly string[]).includes(value);
}

function isRiskTier(value: string): value is RiskTier {
  return (SDK_RISK_TIERS as readonly string[]).includes(value);
}

/**
 * Everything the off-chain attestation doesn't carry but a full, signable
 * on-chain `AttestationPayload` requires — plus explicit overrides for any
 * field whose default derivation you want to bypass.
 *
 * Only `underwriter` is required (there's no on-chain identity in an
 * off-chain attestation). Every other field is either derived from the
 * off-chain content or defaulted, and can be overridden here.
 */
export interface UpgradeToSignedOptions {
  /** Address of the underwriting agent that will sign the on-chain attestation. Required — the off-chain form has no signer identity. */
  underwriter: Address;
  /** Address of the asset issuer/owner. Defaults to the zero address. */
  subject?: Address;
  /** Replay-protection nonce, scoped to `underwriter`. Defaults to `0n`. */
  nonce?: bigint;
  /** Unix expiry (seconds); `0` = never. Defaults to `0`. */
  expiresAt?: number;

  // ---- Overrides for otherwise-derived fields ----

  /** Override the schema version (defaults to the SDK's current schema). */
  schemaVersion?: number;
  /** Override the bytes32 `assetId` (default: keccak256 of the off-chain string `assetId`). */
  assetId?: Hex;
  /** Override the mapped `assetClass` (default: the off-chain value if it's an SDK asset class, else `"other"`). */
  assetClass?: AssetClass;
  /** Override the 0-1000 `riskScore` (default: the off-chain 0-100 `score` * 10). */
  riskScore?: number;
  /** Override the `riskTier` (default: the off-chain `rating` if it's a valid tier — the dapp emits A/B/C/D, all valid). */
  riskTier?: RiskTier;
  /** Override `issuedAt` in unix seconds (default: parsed from the off-chain ISO `issuedAt` string). */
  issuedAt?: number;
  /**
   * Override the supporting-data refs. By default, a single ref committing to
   * the off-chain attestation's SHA-256 content hash is attached, so the
   * signed on-chain attestation is provably tied to the exact off-chain
   * record it was promoted from.
   */
  supportingData?: SupportingDataRef[];
}

/** Type guard: does this off-chain value already carry a precomputed `contentHash`? */
function hasContentHash(value: AttestationContent | OffchainAttestation): value is OffchainAttestation {
  return typeof (value as OffchainAttestation).contentHash === "string" &&
    (value as OffchainAttestation).contentHash.length > 0;
}

/**
 * Promote a dapp-style off-chain attestation to a full EIP-712-signable
 * `AttestationPayload`, ready for `signAttestation` and `verifyAttestation`.
 *
 * This is the bridge between the dapp's current pre-on-chain stage and this
 * SDK's on-chain path: take an `AttestationContent` / `OffchainAttestation`,
 * supply the on-chain-only fields (`underwriter`, and optionally `subject`,
 * `nonce`, `expiresAt`) via `extra`, and get back a payload whose fields are
 * derived from the off-chain content:
 *
 * - `assetId`   ← keccak256 of the off-chain string id (32-byte on-chain id)
 * - `assetClass`← the off-chain class if recognized, else `"other"`
 * - `riskScore` ← off-chain `score` (0-100) * 10  → 0-1000 scale
 * - `riskTier`  ← off-chain `rating` (must be a valid `RiskTier`, or pass `extra.riskTier`)
 * - `issuedAt`  ← the off-chain ISO timestamp parsed to unix seconds
 * - `supportingData` ← a single ref committing to the off-chain SHA-256 content hash
 *
 * Any of these can be overridden via `extra`. Throws if `rating` can't be
 * mapped to a `RiskTier` and no `extra.riskTier` is given, or if `issuedAt`
 * can't be parsed and no `extra.issuedAt` is given — better to fail loudly
 * than silently sign a wrong value.
 */
export function toSignedAttestationPayload(
  offchain: AttestationContent | OffchainAttestation,
  extra: UpgradeToSignedOptions,
): AttestationPayload {
  const assetId = extra.assetId ?? keccak256(stringToHex(offchain.assetId));

  const assetClass = extra.assetClass ?? (isAssetClass(offchain.assetClass) ? offchain.assetClass : "other");

  const riskScore = extra.riskScore ?? offchain.score * 10;

  let riskTier: RiskTier;
  if (extra.riskTier !== undefined) {
    riskTier = extra.riskTier;
  } else if (isRiskTier(offchain.rating)) {
    riskTier = offchain.rating;
  } else {
    throw new Error(
      `Cannot map off-chain rating "${offchain.rating}" to a RiskTier; pass extra.riskTier explicitly.`,
    );
  }

  let issuedAt: number;
  if (extra.issuedAt !== undefined) {
    issuedAt = extra.issuedAt;
  } else {
    const parsed = Math.floor(new Date(offchain.issuedAt).getTime() / 1000);
    if (!Number.isFinite(parsed)) {
      throw new Error(
        `Cannot parse off-chain issuedAt "${offchain.issuedAt}" to a unix timestamp; pass extra.issuedAt explicitly.`,
      );
    }
    issuedAt = parsed;
  }

  // Commit the signed on-chain attestation to the exact off-chain content
  // hash, so the promotion is verifiable end-to-end.
  const contentHash = hasContentHash(offchain) ? offchain.contentHash : hashAttestationContent(offchain);
  const normalizedHash = contentHash.startsWith("0x") ? contentHash.slice(2) : contentHash;
  const contentHashHex = `0x${normalizedHash}` as Hex;
  const attestationId = offchain.attestationId;
  const defaultSupportingData: SupportingDataRef[] = [
    {
      label: "offchain-attestation-content",
      uri: attestationId ? `ledgero:attestation/${attestationId}` : "ledgero:attestation/offchain",
      hash: contentHashHex,
    },
  ];

  return createAttestation({
    schemaVersion: extra.schemaVersion,
    assetClass,
    assetId,
    underwriter: extra.underwriter,
    subject: extra.subject ?? ZERO_ADDRESS,
    riskScore,
    riskTier,
    issuedAt,
    expiresAt: extra.expiresAt ?? 0,
    nonce: extra.nonce ?? 0n,
    supportingData: extra.supportingData ?? defaultSupportingData,
  });
}
