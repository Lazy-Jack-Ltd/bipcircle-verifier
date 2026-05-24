# bipcircle-verifier

Open-source verifier for the **BIPCircle public-reserve-verifier protocol v1**. Anyone can use it to prove a BIPCircle stablecoin reserve attestation PASSes or FAILs — without trusting BIPCircle or Lazy-Jack infrastructure.

The verifier reads primary sources (the XRPL ledger, the bank-service's published JWKS, the witness file in GCS, and the on-chain token contract) and re-derives the same checks BIPCircle's anchor side runs internally. If everything matches, the daily reserve number is provably backed.

## Install

```bash
npm install -g @lazy-jack/bipcircle-verifier
```

Requires Node.js 20+.

## Use

```bash
bipcircle-verify \
    --xrpl-tx <hash> \
    --bank-service-url <https://bank-service-<tenant>.run.app>
```

Output:

```
VERDICT: PASS
  asOfDate: 2026-05-24
  tenantId: tvvin-prod
  sealCount: 24
  signatures: 24/24 OK
  merkle root: OK
```

Exit code `0` on PASS, `1` on FAIL, `2` on invocation error.

For machine-readable output:

```bash
bipcircle-verify --xrpl-tx <hash> --bank-service-url <url> --json
```

## What it actually checks

1. **XRPL transaction** — fetches the daily-attestation tx by hash via public XRPL JSON-RPC. Parses Memo 5 (`reserve-verifier-v1`).
2. **Witness file** — fetches the witness JSON from the URL anchored in Memo 5. Computes SHA-256 of the bytes; rejects if mismatched. Validates schema.
3. **Bank-service public keys** — fetches `/.well-known/bank-service-keys` from the per-tenant bank-service URL you supply. Builds a `kid` → public-key map.
4. **Seal signatures** — for every seal entry in the witness, decodes the canonical input and ECDSA-verifies the signature against the matching public key.
5. **Merkle root** — re-builds the Merkle root from the seal leaf digests and compares it to the root anchored on XRPL. Any tampering anywhere in the witness fails this check.

Each stage produces a structured failure record on FAIL. The `--json` output gives the full diff.

## Trust model

The verifier trusts only:

- **The XRPL ledger** (public, decentralised, permissionless)
- **The bank-service public keys** the operator publishes at their `/.well-known/bank-service-keys` endpoint (HSM-backed ECDSA P-256, FIPS 140-2 Level 3)
- **The witness file's SHA-256** anchored on the immutable XRPL transaction
- **Node.js's built-in crypto** (the verifier uses no external cryptographic dependencies; the canonicalisation, hashing, and signature verification all use the standard library)

The verifier does **not** trust BIPCircle, Lazy-Jack, the bank-service operator, or this binary's source (you can read it, build it, and check the SLSA provenance on every release).

## Protocol

The full protocol specification lives in BIPCircle:

  https://github.com/Lazy-Jack-Ltd/bipcircle/blob/main/Documentation/architecture/public-reserve-verifier-protocol.md

Producer-side source-of-truth:
- bank-service `sealSigner.js` (seal envelope + canonical input)
- BIPCircle `audit.js` (`buildBankServiceSealCanonicalInput`)
- BIPCircle `sealMerkle.js` (Merkle root + witness file shape)
- BIPCircle `publishTenantTreasuryAttestation.js` (XRPL Memo 5 emit)

## Releases + provenance

Every tagged release ships with:

- npm package signed via [npm provenance](https://docs.npmjs.com/generating-provenance-statements) (the build is attested by GitHub Actions on a public runner)
- SHA-256 checksums of the tarball on the GitHub release
- Auto-generated release notes

To verify a downloaded release:

```bash
# Check npm provenance
npm audit signatures @lazy-jack/bipcircle-verifier

# Check the tarball SHA matches the release asset
sha256sum lazy-jack-bipcircle-verifier-*.tgz
```

## Building from source

```bash
git clone https://github.com/Lazy-Jack-Ltd/bipcircle-verifier
cd bipcircle-verifier
npm install
npm test
node bin/bipcircle-verify.js --help
```

No build step — pure JavaScript, runs directly on Node.

## License

MIT — see [LICENSE](./LICENSE).

## What's NOT in this binary today

- **On-chain token supply check.** The `src/onchain.js` module has the JSON-RPC primitives for both Ethereum ERC-20 totalSupply and XRPL issued-currency obligations, but the orchestrator in `src/index.js` doesn't yet call them. Wiring it requires per-tenant config (which contract, which chain) that hasn't yet been pinned in the witness format. Tracked as a 0.2.0 enhancement — for now the verifier proves the bank-side seals are honest; the on-chain comparison runs offline by an auditor with the witness output.

- **Reproducible build.** SLSA provenance attests the build inputs (commit SHA + workflow) but doesn't yet guarantee bit-identical output across builds. A Nix or pnpm-deterministic build is a 0.3.0 target.

These limitations are documented for transparency, not as blockers — the cryptographic guarantees on the bank-service-signed seals are fully load-bearing today.
