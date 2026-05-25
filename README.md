# bipcircle-verifier

Open-source verifier for the **BIPCircle public-reserve-verifier protocol v1**. Anyone can prove a BIPCircle stablecoin reserve attestation PASSes or FAILs without trusting BIPCircle or any Lazy-Jack infrastructure.

The verifier reads primary sources (the XRPL ledger, the bank-service's published JWKS, the witness file in GCS, and the on-chain token contract) and re-derives the same checks BIPCircle's anchor side runs internally. The trust roots are **pinned in the verifier source** — not user input — so a wrong URL or social-engineered tx hash can't produce a false PASS.

## Install

```bash
npm install -g @lazyjackorg/bipcircle-verifier
```

Requires Node.js 20+.

## Use — pinned-tenant mode (preferred)

```bash
bipcircle-verify --xrpl-tx <hash> --tenant <tenantId>
```

The tenant id is looked up in the verifier's pinned `src/tenants.json` registry. Trust roots — bank-service URL, XRPL issuer account, KMS public-key fingerprint pattern, on-chain token contract — all come from the registry. Output:

```
VERDICT: PASS
  asOfDate: 2026-05-24
  tenantId: tvvin-prod
  sealCount: 24
  signatures: 24/24 OK
  merkle root: OK
  reserves: 100245700 | supply: 100245700 | match: ✓
```

The "match ✓" line is the on-chain supply comparison — reserves measured in bank-side minor units (pennies/cents) compared to the on-chain token `totalSupply()`.

## Use — unsafe-override (ad-hoc verification of an unregistered tenant)

```bash
bipcircle-verify \
    --xrpl-tx <hash> \
    --unsafe-bank-service-url https://bank-service-<tenant>.run.app \
    --unsafe-issuer rExampleIssuerAccount...
```

For tenants not yet in the verifier's pinned registry. Operator accepts the trust-anchor responsibility — both the URL and the issuer address need to come from a trusted out-of-band source (DPA, GFSC registry, etc.). On-chain supply check is skipped in this mode (no token-contract config available).

## After PASS — inspect the underlying XRPL transaction

Every successful run prints a `View on XRPL:` line linking to the official XRPL Foundation explorer for the network you specified — `testnet.xrpl.org` or `livenet.xrpl.org`. On an interactive terminal the CLI offers a press-Enter prompt that opens the URL in your operating system's default browser. Pass `--no-open` to suppress the prompt (useful in CI or scripted contexts; the URL is still printed for the log).

The explorer page lets you independently confirm the tx's `Account`, `Memos`, `Sequence`, and ledger-validation state without any platform infrastructure in the loop — useful as a cross-check that the verifier and the XRPL ledger agree.

Exit codes: `0` PASS, `1` FAIL, `2` invocation error. `--json` for machine-readable output (suppresses the explorer prompt regardless of `--no-open`).

## What the verifier actually checks

1. **Registry resolution** — looks up the pinned trust roots for `--tenant` OR validates `--unsafe-*` overrides.
2. **XRPL transaction** — fetches the tx by hash via public JSON-RPC. **Validates `tx.Account === pinned issuer`** (closes Pro F2 cross-account spoofing). Parses Memo 5 (`reserve-verifier-v1`).
3. **Memo kid binding** — verifies the `bankServicePublicKeyId` in Memo 5 matches the tenant's pinned `kidPattern` (closes Pro F1 attacker-controlled URL).
4. **Witness file** — HTTPS GET. Validates SHA-256 of the bytes against `witnessSha256` in Memo 5. Schema check.
5. **Bank-service JWKS** — fetches `/.well-known/bank-service-keys` from the **pinned** bankServiceUrl. Validates every advertised `kid` matches the tenant's `kidPattern`. Rejects duplicate kids; pins `alg=ES256`.
6. **Seal signatures** — for every seal in the witness, decodes the canonical input and ECDSA-verifies the signature against the matching public key.
7. **Merkle root** — re-builds the Merkle root from leaf digests; compares to Memo 5's anchored root.
8. **On-chain supply** — fetches token `totalSupply()` from the chain in the tenant registry; compares to the sum of bank-side balances. Reports "match ✓" or "shortfall of N minor units."

Every stage produces a structured failure record on FAIL. `--json` gives the full diff.

## Trust model

The verifier trusts only:

- **This verifier's pinned tenant registry** (`src/tenants.json`, ships in the source release; operator-PR'd as tenants onboard)
- **The XRPL ledger** (public, permissionless)
- **The bank-service public keys** the operator publishes at the pinned `/.well-known/bank-service-keys` endpoint (HSM-backed ECDSA P-256, FIPS 140-2 Level 3)
- **The witness file's SHA-256** anchored on the immutable XRPL transaction
- **Node.js's built-in crypto** (no external cryptographic dependencies)

The verifier does **not** trust BIPCircle, Lazy-Jack, the bank-service operator, the GCS witness host, or this binary's source (you can read it, build it, and check the npm + SLSA provenance on every release).

## Protocol

  https://github.com/Lazy-Jack-Ltd/bipcircle/blob/main/Documentation/architecture/public-reserve-verifier-protocol.md

Producer-side source-of-truth:
- bank-service `sealSigner.js` (seal envelope + canonical input)
- BIPCircle `audit.js` `buildBankServiceSealCanonicalInput`
- BIPCircle `sealMerkle.js` (Merkle root + witness file shape)
- BIPCircle `publishTenantTreasuryAttestation.js` (XRPL Memo 5 emit)

## Releases + provenance

Every tagged release ships with:

- npm package signed via [npm provenance](https://docs.npmjs.com/generating-provenance-statements) (build attested by GitHub Actions OIDC on a public runner)
- SHA-256 checksums of the tarball on the GitHub release
- Auto-generated release notes

To verify a downloaded release:

```bash
npm audit signatures @lazyjackorg/bipcircle-verifier
sha256sum lazy-jack-bipcircle-verifier-*.tgz
```

## Adding a tenant

Tenants are pinned in source: every release embeds the registry available at release time. To onboard a new tenant:

1. Open a PR to `src/tenants.json` adding the entry:

   ```json
   {
     "tenantId": "your-tenant-id",
     "bankServiceUrl": "https://bank-service-your-tenant.run.app",
     "xrplIssuerAddress": "rYourTreasuryWalletAddress...",
     "kidPattern": "^projects/your-gcp-project/locations/europe-west2/keyRings/bank-service-signers/cryptoKeys/your-tenant-signer/cryptoKeyVersions/\\d+$",
     "token": {
       "chain": "ethereum",
       "contract": "0xYourErc20Address...",
       "decimals": 2,
       "currency": "GBP"
     }
   }
   ```

2. Cut a new verifier release (bump the patch / minor). External verifiers upgrade when ready.

Until the new release lands, third parties can verify your tenant using `--unsafe-bank-service-url` + `--unsafe-issuer` overrides.

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

## Audit history

- **v0.1.0** — initial release
- **v0.1.1** — self-audit pass: fetch timeouts on every external call (10s/15s/30s), CLI `--key=value` form, witness `sealCount` type check
- **v0.1.2** — Gemini Pro adversarial audit + external reviewer feedback:
  - **F1 (CRITICAL) + F2 (CRITICAL) closed**: pinned per-tenant registry binds bank-service URL + XRPL issuer + kid pattern in the verifier source (not user input). Closes both the user-supplied-URL trust gap AND the accept-any-XRPL-account spoofing path.
  - **F4 (MEDIUM) closed**: JWKS now rejects duplicate kids + pins `alg=ES256` strictly.
  - **0.2.0 forward-port**: on-chain `totalSupply()` comparison wired in via tenant registry's token config. Output now reports `reserves = X | supply = Y | match ✓` or shortfall.
  - **F7 (test coverage) closed**: 21 tests (up from 14) including F1/F2/F4 regressions + signature-forgery + duplicate-kid + unknown-tenant + wrong-XRPL-account adversarial paths.
  - False positives documented in the commit message (nested-key canonicalisation, Merkle reorder, try/catch on crypto.verify — none were real issues; verifier doesn't re-canonicalise, witnessSha256 binds bytes, try/catch was already present).
- **v0.1.3** — first pinned tenant + XRPL explorer UX:
  - **`tvvin` tenant pinned in `src/tenants.json`** — the testnet Sepolia ERC-3643 stablecoin issuer at `0xDc48900756dB73D795cd5C9Fcb6CAABe33De27c4`, XRPL issuer `rat8BjsVkGpWS44tg89QxMmNWjgduw6Ym4`, bank-service URL `https://bank-service-tvvin-yrikeqyelq-nw.a.run.app`. First end-to-end verification against this tenant landed PASS on tx `7753CF92C7C017D2C9C721F1A72F3BEA55030DD655D6377E7750C757FB711E57`.
  - **XRPL explorer URL in the CLI output** — every successful run now prints `View on XRPL: https://testnet.xrpl.org/transactions/<hash>` (mainnet: `livenet.xrpl.org`). On an interactive TTY the CLI also offers a press-Enter prompt to launch the URL in the operating system's default browser. Add `--no-open` to suppress the prompt for CI / scripted contexts.

Reproducible builds (bit-identical output) remain a 0.3.0 target.
