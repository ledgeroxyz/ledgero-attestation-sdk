import { privateKeyToAccount } from "viem/accounts";
import type { Hex, LocalAccount } from "viem";
import type { AttestationDomain, AttestationPayload } from "./types.js";
import { ATTESTATION_EIP712_TYPES, ATTESTATION_PRIMARY_TYPE, toAttestationMessage } from "./eip712.js";
import { toViemDomain } from "./domain.js";

/**
 * Anything that can produce an attestation signature: either a raw
 * `0x`-prefixed private key (convenient for scripts/agents/tests — never
 * pass a real key from user input), or an already-constructed viem
 * `LocalAccount` (e.g. from `privateKeyToAccount`, a hardware wallet
 * adapter, or a KMS-backed account implementation).
 */
export type AttestationSigner = Hex | LocalAccount;

function resolveAccount(signer: AttestationSigner): LocalAccount {
  if (typeof signer === "string") {
    return privateKeyToAccount(signer);
  }
  return signer;
}

/**
 * Build the full EIP-712 typed-data object (`domain` + `types` +
 * `primaryType` + `message`) for an attestation, ready to pass to any
 * viem/EIP-712-compatible signer (`account.signTypedData`, a wallet client,
 * a browser wallet's `eth_signTypedData_v4`, etc).
 */
export function buildAttestationTypedData(payload: AttestationPayload, domain: AttestationDomain) {
  return {
    domain: toViemDomain(domain),
    types: ATTESTATION_EIP712_TYPES,
    primaryType: ATTESTATION_PRIMARY_TYPE,
    message: toAttestationMessage(payload),
  } as const;
}

/**
 * Sign an attestation payload as EIP-712 typed data, producing the
 * signature bytes a verifier can check with `verifyAttestation`.
 *
 * @param signer a raw private key or a viem `LocalAccount`
 */
export async function signAttestation(
  payload: AttestationPayload,
  domain: AttestationDomain,
  signer: AttestationSigner,
): Promise<Hex> {
  const account = resolveAccount(signer);
  const typedData = buildAttestationTypedData(payload, domain);
  return account.signTypedData(typedData);
}
