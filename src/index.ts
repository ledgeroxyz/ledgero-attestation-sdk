// Types & schema
export type {
  AssetClass,
  RiskTier,
  SupportingDataRef,
  AttestationPayload,
  NewAttestationInput,
  AttestationDomain,
  EncodedAttestation,
} from "./types.js";
export { ATTESTATION_SCHEMA_VERSION, createAttestation } from "./types.js";

// Constants
export { ZERO_BYTES32, ZERO_ADDRESS } from "./constants.js";

// EIP-712 domain
export { DEFAULT_DOMAIN_NAME, DEFAULT_DOMAIN_VERSION, createAttestationDomain, toViemDomain } from "./domain.js";

// EIP-712 typed-data shape
export type { AttestationTypedMessage } from "./eip712.js";
export {
  ATTESTATION_PRIMARY_TYPE,
  ATTESTATION_EIP712_TYPES,
  hashSupportingData,
  toAttestationMessage,
} from "./eip712.js";

// Canonical hashing
export { hashAttestation } from "./hash.js";

// Signing
export type { AttestationSigner } from "./sign.js";
export { buildAttestationTypedData, signAttestation } from "./sign.js";

// Verification
export type { VerifyAttestationOptions, VerifyAttestationResult } from "./verify.js";
export { verifyAttestation, isExpired } from "./verify.js";

// On-chain-ready encoding
export { encodeAttestation, decodeAttestation } from "./encode.js";
