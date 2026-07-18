import { z } from "zod";

/** `0x`-prefixed, 32-byte (64 hex char) value — asset IDs, content hashes, `supersedes`, etc. */
const hex32Schema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{64}$/, "must be a 0x-prefixed 32-byte hex string (64 hex chars)");

/** `0x`-prefixed, 20-byte (40 hex char) EVM address. */
const addressSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40}$/, "must be a 0x-prefixed 20-byte hex address (40 hex chars)");

const assetClassSchema = z.enum(["invoice", "receivable", "real_estate", "inventory", "other"]);

const riskTierSchema = z.enum(["AAA", "AA", "A", "BBB", "BB", "B", "CCC", "CC", "C", "D"]);

/** Zod schema for a single `SupportingDataRef`. */
export const supportingDataRefSchema = z.object({
  label: z.string().min(1, "label must not be empty"),
  uri: z.string().min(1, "uri must not be empty"),
  hash: hex32Schema,
});

/**
 * Runtime (zod) schema for `AttestationPayload`. Mirrors the TypeScript
 * type in `types.ts` field-for-field, including the optional `supersedes`
 * link. Useful for validating untrusted/deserialized JSON (e.g. an
 * attestation received over the network or loaded from storage) before
 * it's signed, or after it's decoded and before it's trusted.
 *
 * This validates *shape and value ranges*, not signatures — pair with
 * `verifyAttestation` (or `verifyAttestationWithRevocation`) for
 * cryptographic verification once you know the shape is sound.
 */
export const attestationPayloadSchema = z.object({
  schemaVersion: z.number().int().nonnegative(),
  assetClass: assetClassSchema,
  assetId: hex32Schema,
  underwriter: addressSchema,
  subject: addressSchema,
  riskScore: z.number().int().min(0, "riskScore must be in the 0-1000 range").max(1000, "riskScore must be in the 0-1000 range"),
  riskTier: riskTierSchema,
  issuedAt: z.number().int().nonnegative("issuedAt must be a non-negative unix timestamp"),
  expiresAt: z.number().int().nonnegative("expiresAt must be a non-negative unix timestamp (0 = never expires)"),
  nonce: z.bigint().nonnegative("nonce must be a non-negative bigint"),
  supportingData: z.array(supportingDataRefSchema),
  supersedes: hex32Schema.optional(),
});

/** Result of `validateAttestationPayload`. */
export interface ValidateAttestationPayloadResult {
  valid: boolean;
  /** Human-readable `"<path>: <message>"` strings, one per validation failure. Empty when `valid` is `true`. */
  errors: string[];
}

/**
 * Validate an untrusted/deserialized value against the `AttestationPayload`
 * shape at runtime (via `attestationPayloadSchema`). Unlike the TypeScript
 * type, this actually inspects the value — useful right after
 * `JSON.parse`-ing an attestation from the network or storage, before
 * trusting its shape enough to hash, sign, or verify it.
 *
 * Note `nonce` (a `bigint`) is not representable in plain JSON — if you're
 * validating a JSON-deserialized payload, convert `nonce` from its
 * string/number wire form to a `bigint` first.
 */
export function validateAttestationPayload(payload: unknown): ValidateAttestationPayloadResult {
  const result = attestationPayloadSchema.safeParse(payload);
  if (result.success) {
    return { valid: true, errors: [] };
  }

  const errors = result.error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join(".") : "(root)";
    return `${path}: ${issue.message}`;
  });

  return { valid: false, errors };
}
