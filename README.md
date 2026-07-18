# @ledgeroxyz/attestation-sdk

TypeScript SDK for building, hashing, signing, and verifying **LEDGERO underwriting attestations** — the signed, verifiable record LEDGERO's AI underwriting agent emits after assessing a real-world asset (RWA) for tokenization.

This is a pure data/crypto utility library:

- No UI.
- No smart contract code (no Solidity) — it produces the encoding a contract would consume/emit, nothing more.
- No network calls — everything here is deterministic, local computation over data you already have.

It's designed to be a small, dependable building block that anyone — LEDGERO's own services, or third-party issuers, lenders, and protocols — can use to produce or consume LEDGERO-style attestations without re-implementing the hashing/signing scheme themselves.

## Why this exists

LEDGERO ($LDGR) is an AI underwriting agent for RWA tokenization. Given source documents for a candidate asset (an invoice, a receivable, a property, inventory), it:

1. Ingests and OCRs/extracts structured fields from those documents.
2. Runs a structured risk assessment (see the companion `risk-sdk` for scoring).
3. Cross-references external data.
4. Emits a signed, verifiable **attestation** — the underwriting record that issuers, lenders, and protocols can trust and build on.

`@ledgeroxyz/attestation-sdk` implements step 4 in isolation: the schema for that attestation record, how it's canonically hashed, how it's signed as EIP-712 typed data, how a signature is verified, and how the record is encoded into the compact form a smart contract would store or emit on-chain.

## Install

```bash
pnpm add @ledgeroxyz/attestation-sdk viem
```

`viem` is a peer dependency in spirit (declared as a direct dependency here for simplicity) — it supplies the underlying typed-data hashing, signing, and address-recovery primitives.

## Quickstart

### Build a payload

```ts
import { createAttestation, ZERO_ADDRESS } from "@ledgeroxyz/attestation-sdk";
import { keccak256, stringToHex } from "viem";

const payload = createAttestation({
  assetClass: "invoice",
  assetId: keccak256(stringToHex("invoice-INV-2026-0042")),
  underwriter: "0xUnderwriterAgentAddress...",
  subject: ZERO_ADDRESS, // or the asset issuer's address
  riskScore: 742, // 0-1000 scale (basis-point-style precision on a 0-100 score)
  riskTier: "BBB",
  issuedAt: Math.floor(Date.now() / 1000),
  expiresAt: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365, // 1 year, or 0 for "never"
  nonce: 1n,
  supportingData: [
    {
      label: "invoice-pdf",
      uri: "ipfs://bafybe.../invoice.pdf",
      hash: keccak256(stringToHex("<invoice pdf bytes>")),
    },
  ],
});
```

### Sign it

```ts
import { createAttestationDomain, signAttestation } from "@ledgeroxyz/attestation-sdk";

const domain = createAttestationDomain({
  chainId: 8453, // Base, or wherever attestations are anchored
  verifyingContract: "0xYourAttestationRegistryContract...",
});

// Sign with a raw private key...
const signature = await signAttestation(payload, domain, "0xabc123...privateKey");

// ...or with any viem LocalAccount (hardware wallet adapter, KMS-backed
// account, etc — anything implementing viem's Account.signTypedData).
```

### Verify it

```ts
import { verifyAttestation } from "@ledgeroxyz/attestation-sdk";

const result = await verifyAttestation(payload, domain, signature);

if (result.valid) {
  console.log("Signed by:", result.signer);
} else {
  console.error("Invalid attestation:", result.reason);
}
```

`verifyAttestation` checks, in order: that the signature recovers to an address at all, that it matches the expected signer (defaults to `payload.underwriter`, or pass `expectedSigner` to check against something else), and — unless `checkExpiry: false` is passed — that the attestation hasn't expired. It always resolves to a result object (`{ valid, signer?, reason? }`) rather than throwing, so callers get a single place to branch on any failure mode.

### Content hash (for on-chain reference / dedup)

```ts
import { hashAttestation } from "@ledgeroxyz/attestation-sdk";

const contentHash = hashAttestation(payload); // deterministic, domain-independent
```

This is distinct from the EIP-712 signing hash: `hashAttestation` answers "what is this attestation's content?" (useful as a content-addressed key, independent of who signed it or under what domain), while the EIP-712 hash used internally by `signAttestation`/`verifyAttestation` additionally binds the domain separator (chain ID, verifying contract, domain name/version).

### On-chain-ready encoding

```ts
import { encodeAttestation, decodeAttestation } from "@ledgeroxyz/attestation-sdk";

const encoded = encodeAttestation(payload); // ABI-encoded bytes, e.g. for a contract call/event
const decoded = decodeAttestation(encoded); // scalar fields + supportingDataHash commitment
```

`encodeAttestation` ABI-encodes the attestation into the compact tuple a smart contract would store or emit. Because `supportingData` is a dynamic array, it's committed to as a single `bytes32` (`supportingDataHash`, via `hashSupportingData`) rather than embedded field-by-field — the same tradeoff the EIP-712 struct makes. `decodeAttestation` is therefore lossy relative to the original payload: it recovers every scalar field plus the `supportingDataHash` commitment, but not the underlying `supportingData` array itself (by design — that data is expected to live off-chain, with its hash checked against the commitment).

## API overview

| Export | Purpose |
|---|---|
| `AttestationPayload`, `AttestationDomain`, `SupportingDataRef`, `EncodedAttestation` | Core types |
| `AssetClass`, `RiskTier` | Field vocabularies |
| `ATTESTATION_SCHEMA_VERSION`, `createAttestation` | Schema version constant + payload constructor |
| `createAttestationDomain`, `toViemDomain` | Build an EIP-712 domain |
| `ATTESTATION_EIP712_TYPES`, `ATTESTATION_PRIMARY_TYPE`, `toAttestationMessage`, `hashSupportingData` | EIP-712 typed-data building blocks |
| `hashAttestation` | Canonical, domain-independent content hash |
| `signAttestation`, `buildAttestationTypedData`, `AttestationSigner` | Sign as EIP-712 typed data |
| `verifyAttestation`, `isExpired`, `VerifyAttestationResult` | Verify a signature (+ optional expiry check) |
| `encodeAttestation`, `decodeAttestation` | ABI encode/decode the compact on-chain form |
| `ZERO_ADDRESS`, `ZERO_BYTES32` | Convenience constants |

Everything is exported from the package root:

```ts
import { /* ... */ } from "@ledgeroxyz/attestation-sdk";
```

## Schema versioning

Every `AttestationPayload` carries a `schemaVersion` field (`ATTESTATION_SCHEMA_VERSION` in this version of the SDK). This library does **not** silently migrate or interpret older/newer schema versions for you — if you're consuming attestations from elsewhere, check `schemaVersion` yourself before trusting the shape of the rest of the payload. Breaking changes to the field layout (and therefore to the EIP-712 struct and ABI-encoded form) will bump this constant.

## Compatibility with `@ledgeroxyz/risk-sdk`

`riskScore` and `riskTier` are deliberately shaped to be a drop-in target for the `ScoreResult` produced by LEDGERO's risk-sdk (structured risk assessment): `riskTier` shares its string vocabulary with `ScoreResult.tier`, and `riskScore` is a `0-1000` integer — multiply a `0-100` float score by `10` when populating it. This package does **not** import or depend on `risk-sdk`; the compatibility is a documented convention, not a hard dependency, so this SDK stays usable standalone.

## Development

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm build
```

## License

MIT © ledgeroxyz
