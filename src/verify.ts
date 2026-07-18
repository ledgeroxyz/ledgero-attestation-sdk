import { recoverTypedDataAddress } from "viem";
import type { Address, Hex } from "viem";
import type { AttestationDomain, AttestationPayload } from "./types.js";
import { buildAttestationTypedData } from "./sign.js";

export interface VerifyAttestationOptions {
  /**
   * If provided, the recovered signer must match this address exactly
   * (case-insensitively). If omitted, defaults to requiring the recovered
   * signer to match `payload.underwriter`.
   */
  expectedSigner?: Address;
  /** Unix timestamp (seconds) to check expiry against. Defaults to the current time. */
  now?: number;
  /** Whether to check `payload.expiresAt`. Defaults to `true`. */
  checkExpiry?: boolean;
}

export interface VerifyAttestationResult {
  valid: boolean;
  /** The address recovered from the signature, if recovery succeeded. */
  signer?: Address;
  /** Human-readable reason the verification failed. Absent when `valid` is `true`. */
  reason?: string;
}

/**
 * Verify a signature over an attestation payload: recovers the signer from
 * the EIP-712 typed-data signature and checks it against the expected
 * signer (either an explicit `expectedSigner` or, by default,
 * `payload.underwriter`), plus optionally checks expiry.
 *
 * Always returns a result object rather than throwing — `valid: false` with
 * a `reason` covers both "signature doesn't recover" and "recovered but
 * wrong signer / expired", so callers get a single place to branch on.
 */
export async function verifyAttestation(
  payload: AttestationPayload,
  domain: AttestationDomain,
  signature: Hex,
  options: VerifyAttestationOptions = {},
): Promise<VerifyAttestationResult> {
  const { expectedSigner, now = Math.floor(Date.now() / 1000), checkExpiry = true } = options;

  const typedData = buildAttestationTypedData(payload, domain);

  let signer: Address;
  try {
    signer = await recoverTypedDataAddress({ ...typedData, signature });
  } catch (err) {
    return { valid: false, reason: `signature recovery failed: ${(err as Error).message}` };
  }

  const requiredSigner = expectedSigner ?? payload.underwriter;
  if (signer.toLowerCase() !== requiredSigner.toLowerCase()) {
    return {
      valid: false,
      signer,
      reason: expectedSigner
        ? "recovered signer does not match expectedSigner"
        : "recovered signer does not match payload.underwriter",
    };
  }

  if (checkExpiry && isExpired(payload, now)) {
    return { valid: false, signer, reason: "attestation expired" };
  }

  return { valid: true, signer };
}

/** Whether an attestation is past its `expiresAt`. `expiresAt === 0` means "never expires". */
export function isExpired(payload: AttestationPayload, now: number = Math.floor(Date.now() / 1000)): boolean {
  return payload.expiresAt !== 0 && now > payload.expiresAt;
}
