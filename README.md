# @ledgeroxyz/attestation-sdk

TypeScript SDK for building, hashing, signing, and verifying **LEDGERO underwriting attestations** — the signed, verifiable record LEDGERO's AI underwriting agent emits after assessing a real-world asset (RWA) for tokenization.

This is a pure data/crypto utility library:

- No UI.
- No smart contract code (no Solidity) — it produces the encoding a contract would consume/emit, nothing more.
- No network calls — everything here is deterministic, local computation over data you already have.

It's designed to be a small, dependable building block that anyone — LEDGERO's own services, or third-party issuers, lenders, and protocols — can use to produce or consume LEDGERO-style attestations without re-implementing the hashing/signing scheme themselves.

## Why this exists

LEDGERO ($LEDGER) is an AI underwriting agent for RWA tokenization. Given source documents for a candidate asset (an invoice, a receivable, a property, inventory), it:

1. Ingests and OCRs/extracts structured fields from those documents.
2. Runs a structured risk assessment (see the companion `risk-sdk` for scoring).
3. Cross-references external data.
4. Emits a signed, verifiable **attestation** — the underwriting record that issuers, lenders, and protocols can trust and build on.

`@ledgeroxyz/attestation-sdk` implements step 4 in isolation: the schema for that attestation record, how it's canonically hashed, how it's signed as EIP-712 typed data, how a signature is verified, and how the record is encoded into the compact form a smart contract would store or emit on-chain.

## Install

```bash
pnpm add @ledgeroxyz/attestation-sdk viem
```

`viem` is a peer dependency in spirit (declared as a direct dependency here for simplicity) — it supplies the underlying typed-data hashing, signing, and address-recovery primitives. `zod` is also a direct dependency, used internally by `validateAttestationPayload` (see [Runtime payload validation](#runtime-payload-validation)) — you don't need to install it yourself.

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

### Batch verification

```ts
import { verifyAttestationBatch } from "@ledgeroxyz/attestation-sdk";

const { results, stats } = await verifyAttestationBatch([
  { payload: payloadA, signature: sigA, domain },
  { payload: payloadB, signature: sigB, domain },
  { payload: payloadC, signature: sigC, domain, options: { expectedSigner: someOtherAddress } },
]);

console.log(stats); // { total: 3, valid: 2, invalid: 1, expired: 0 }

for (const result of results) {
  // result.index is the item's position in the input array
  if (!result.valid) console.warn(`item ${result.index} failed:`, result.reason);
}
```

`verifyAttestationBatch` verifies every item concurrently via `verifyAttestation` (a bad/malformed item can't affect the others), preserves input order in `results`, and rolls up aggregate `stats` — handy for bulk ingestion or audit flows over attestations pulled from storage or received over the network.

### Revocation

```ts
import {
  RevocationRegistry,
  hashAttestation,
  verifyAttestationWithRevocation,
} from "@ledgeroxyz/attestation-sdk";

const registry = new RevocationRegistry(); // in-memory by default

// Later, an underwriter decides an attestation was wrong and withdraws it:
registry.revoke(hashAttestation(payload), "re-underwritten with corrected documents");

// A verifier composes signature + revocation checks in one call:
const result = await verifyAttestationWithRevocation(payload, domain, signature, registry);

if (!result.valid) {
  console.error(result.reason); // e.g. "attestation revoked: re-underwritten with corrected documents"
}

registry.isRevoked(hashAttestation(payload)); // true
registry.listRevoked(); // RevocationRecord[]
```

`RevocationRegistry` tracks revocations by an attestation's content hash (`hashAttestation`), so a signature that's still cryptographically valid can still be rejected once the underlying record is withdrawn. It's backed by a pluggable `RevocationStore` interface (default: an in-memory `Map`, via `InMemoryRevocationStore`) — implement `RevocationStore` yourself to persist revocations in a database, KV store, or on-chain registry.

### Supersede/amend chaining

An attestation can optionally name a prior attestation it amends via `supersedes` — the content hash (`hashAttestation`) of the attestation it replaces:

```ts
import { createAttestation, hashAttestation } from "@ledgeroxyz/attestation-sdk";

const original = createAttestation({ /* ... */ riskScore: 700, nonce: 1n /* ... */ });

const corrected = createAttestation({
  /* ... */
  riskScore: 650, // corrected after new documents came in
  nonce: 2n,
  supersedes: hashAttestation(original),
});
```

`buildAmendmentChain` resolves a set of attestations linked this way into a single ordered chain (oldest → newest), and `validateAttestationChain` is a thin wrapper for callers who just want a valid/invalid verdict:

```ts
import { buildAmendmentChain, validateAttestationChain } from "@ledgeroxyz/attestation-sdk";

const { valid, chain, latest, reason } = buildAmendmentChain([original, corrected]);
// valid: true, chain: [original, corrected] (oldest -> newest), latest: corrected

validateAttestationChain([original, corrected]); // { valid: true }
```

`buildAmendmentChain` detects and reports (via `reason`) malformed input sets: an empty set, duplicate attestations, an **ambiguous** set (more than one un-superseded/"head" attestation — i.e. a fork), and a **cycle** in the `supersedes` links. A `supersedes` value that points outside the given input set is treated as the chain's boundary (not an error) — the referenced attestation is presumably known/verified elsewhere.

`supersedes` is optional and defaults to absent — existing code that doesn't use amendment chaining is unaffected. Note that because `supersedes` is part of the hashed/signed payload, it participates in `ATTESTATION_SCHEMA_VERSION` (see [Schema versioning](#schema-versioning)).

### Runtime payload validation

```ts
import { validateAttestationPayload } from "@ledgeroxyz/attestation-sdk";

// e.g. right after JSON.parse-ing an attestation received over the network
const untrusted = JSON.parse(rawJson);
untrusted.nonce = BigInt(untrusted.nonce); // JSON has no bigint — convert first

const { valid, errors } = validateAttestationPayload(untrusted);

if (!valid) {
  console.error("invalid attestation payload:", errors);
  // e.g. ["riskScore: riskScore must be in the 0-1000 range", "underwriter: must be a 0x-prefixed 20-byte hex address (40 hex chars)"]
}
```

`validateAttestationPayload` checks an `unknown` value against a [zod](https://zod.dev) schema (`attestationPayloadSchema`, also exported directly if you want to compose it into a larger schema) mirroring `AttestationPayload` field-for-field — field types, hex/address formats, enum vocabularies, and numeric ranges. This is a **shape** check, not a cryptographic one: pair it with `verifyAttestation`/`verifyAttestationWithRevocation` once you know a payload is well-formed enough to be worth checking a signature against.

## Off-chain attestations & dapp alignment

Everything above describes a **fully signed, EIP-712 on-chain-ready** attestation — it needs an underwriter key (or `LocalAccount`) to sign. But an issuer often has an earlier, **pre-on-chain** stage: the assessment has run and produced a verifiable record, but there's no signing key or chain anchor yet. This is exactly where the [LEDGERO dapp](https://ledgero.xyz) sits today — it issues an attestation by computing a **SHA-256 content hash** over the assessed fields (no EIP-712, no private key) and storing that hash as a tamper-evident "faithful stand-in for a signed, verifiable record."

This SDK models that stage directly, so the dapp (and anyone else) can adopt the SDK without first standing up a signer — and later **promote** the same record to a full signed attestation without re-deriving anything.

### Issue an off-chain (content-hash) attestation

```ts
import { createOffchainAttestation, hashAttestationContent, verifyContentHash } from "@ledgeroxyz/attestation-sdk";

const content = {
  assetId: "asset_9f2c1a7b4e6d4c3f",
  name: "Series A Invoice — Acme Corp",
  assetClass: "invoice",
  claimedValue: 250_000,
  score: 72,          // 0-100 scale
  rating: "B",        // A | B | C | D
  issuedAt: new Date().toISOString(),
};

const attestation = createOffchainAttestation(content);
// -> { ...content, attestationId: "att_<uuid>", contentHash: "<64-char sha256 hex>" }

// Or just the hash:
const hash = hashAttestationContent(content);
verifyContentHash(content, hash); // true
```

**The hashed field set and order are load-bearing.** `hashAttestationContent` computes SHA-256 over `JSON.stringify` of exactly these fields, in exactly this order:

```
assetId, name, assetClass, claimedValue, score, rating, issuedAt
```

This matches the LEDGERO dapp's `runAssessment` **byte-for-byte** — the returned hash is **un-prefixed, lowercase hex** (64 chars), the same format the dapp stores as `attestationHash`. (viem's `sha256` returns `0x`-prefixed hex; the prefix is stripped so the two agree exactly. There's a test asserting equivalence against the dapp's SHA-256-over-canonical-JSON algorithm.) `attestationId` is deliberately **not** part of the hashed content — it identifies the record, it isn't assessed data. `canonicalAttestationContent` emits the fields in the fixed order regardless of your input object's key order, so callers can't accidentally produce a different hash by ordering keys differently.

If you need a `bytes32` for on-chain use, prepend `0x` — SHA-256 is 32 bytes, so `0x<contentHash>` is a valid `bytes32`.

### Promote an off-chain attestation to a signed on-chain one

When the issuer is ready to sign and anchor on-chain, `toSignedAttestationPayload` maps a dapp-style off-chain attestation into a full `AttestationPayload`, which you then sign with the existing `signAttestation`:

```ts
import {
  createOffchainAttestation,
  toSignedAttestationPayload,
  createAttestationDomain,
  signAttestation,
  verifyAttestation,
  ZERO_ADDRESS,
} from "@ledgeroxyz/attestation-sdk";

const offchain = createOffchainAttestation(content);

// Supply the on-chain-only fields; everything else is derived from `offchain`.
const payload = toSignedAttestationPayload(offchain, {
  underwriter: "0xUnderwriterAgentAddress...", // required
  subject: ZERO_ADDRESS,                        // optional (default: zero address)
  nonce: 1n,                                     // optional (default: 0n)
  expiresAt: 0,                                  // optional (default: 0 = never)
});

const domain = createAttestationDomain({ chainId: 8453, verifyingContract: "0xRegistry..." });
const signature = await signAttestation(payload, domain, "0x...privateKey");
const result = await verifyAttestation(payload, domain, signature); // { valid: true, ... }
```

How each on-chain field is derived from the off-chain content (all overridable via the second argument):

| On-chain field | Derived from | Rule |
|---|---|---|
| `assetId` (`bytes32`) | off-chain `assetId` string | `keccak256(stringToHex(assetId))` |
| `assetClass` | off-chain `assetClass` | passed through if a recognized `AssetClass`, else `"other"` |
| `riskScore` (0-1000) | off-chain `score` (0-100) | `score * 10` |
| `riskTier` | off-chain `rating` | passed through if a valid `RiskTier` (the dapp's A/B/C/D all are); throws if unmappable and no `riskTier` override |
| `issuedAt` (unix s) | off-chain `issuedAt` (ISO) | `Date.parse(...) / 1000`; throws if unparseable and no `issuedAt` override |
| `supportingData` | off-chain `contentHash` | one ref committing to the off-chain SHA-256 content hash, tying the signed record to the exact off-chain record it was promoted from |

The default `supportingData` ref means a verifier of the **signed** attestation can re-derive the original off-chain `contentHash` (via `hashAttestationContent`) and confirm it matches the committed `bytes32` — the off-chain and on-chain records are provably the same underwriting. Only `underwriter` is required; anything the derivation gets wrong for your use case can be overridden explicitly.

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
| `verifyAttestationBatch`, `BatchAttestationItem`, `BatchVerificationResult` | Verify many attestations concurrently, with aggregate stats |
| `RevocationRegistry`, `InMemoryRevocationStore`, `RevocationStore`, `verifyAttestationWithRevocation` | Track and check revoked attestations by content hash |
| `buildAmendmentChain`, `validateAttestationChain`, `AttestationChainEntry`, `AttestationChainResult` | Resolve a `supersedes`-linked set of attestations into an ordered amendment chain |
| `validateAttestationPayload`, `attestationPayloadSchema`, `supportingDataRefSchema` | Runtime (zod) shape validation for an untrusted/deserialized `AttestationPayload` |
| `AttestationContent`, `OffchainAttestation` | Types for signer-free, content-hash (dapp-aligned) attestations |
| `hashAttestationContent`, `canonicalAttestationContent`, `verifyContentHash` | Dapp-equivalent SHA-256 content hash over the canonical field order |
| `createOffchainAttestation`, `newAttestationId` | Build an off-chain attestation record / generate an `att_<uuid>` id |
| `toSignedAttestationPayload`, `UpgradeToSignedOptions` | Promote an off-chain attestation to a full EIP-712-signable `AttestationPayload` |
| `ZERO_ADDRESS`, `ZERO_BYTES32` | Convenience constants |

Everything is exported from the package root:

```ts
import { /* ... */ } from "@ledgeroxyz/attestation-sdk";
```

## Schema versioning

Every `AttestationPayload` carries a `schemaVersion` field (`ATTESTATION_SCHEMA_VERSION` in this version of the SDK). This library does **not** silently migrate or interpret older/newer schema versions for you — if you're consuming attestations from elsewhere, check `schemaVersion` yourself before trusting the shape of the rest of the payload. Breaking changes to the field layout (and therefore to the EIP-712 struct and ABI-encoded form) will bump this constant.

- **`2`** (current): adds the optional `supersedes` field (see [Supersede/amend chaining](#supersedeamend-chaining)) to the EIP-712 struct and ABI-encoded/hashed form. `supersedes` is optional at the TypeScript level and defaults to the zero hash when absent, so source code using this SDK doesn't need to change — but because it's part of the signed/hashed struct, the bytes produced by `encodeAttestation`/`hashAttestation` differ from what schema `1` of this SDK produced, even for payloads that don't set `supersedes`. Verifiers needing byte-for-byte compatibility with a specific prior release should branch on `schemaVersion`.
- **`1`**: initial release — `AttestationPayload` without `supersedes`.

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
