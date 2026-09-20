# Changelog

All notable changes to `@lazyjackorg/bipcircle-verifier`.

> **Publishing state:** npm `latest` is **0.4.0**. Versions **0.5.0** and **0.6.0**
> were developed, committed and tagged nowhere — they exist in git history but were
> never published, so no third party has ever run them. 0.7.0 is therefore the first
> release to carry the 0.5.0 and 0.6.0 work, and the notes for all three are below.

## [0.7.0] — 2026-09-20

**The registry conflated two on-chain identities, and every genuine attestation failed because of it.**

### Fixed — the publishing account is not the token issuer

`src/tenants.json` pinned the XRPL **token issuer** (`rD1ggC6…`) as the account a daily
attestation transaction must be signed by. The producer signs from a separate per-tenant
anchor wallet (`fund_tenants/{id}.xrplAttestationWallet.address`), which for the live
deployment is `rL78qv…`. Every attestation the platform has ever published therefore
failed the F2 account-binding check. The verifier was not verifying anything.

The field was also *named* for the confusion — `xrplIssuerAddress` — so the fix is a rename,
not just a value change:

- `xrplIssuerAddress` → **`xrplPublishingAccount`**. The old name is still read as a
  deprecated alias (silently dropping a third-party entry's F2 gate would be worse), but an
  entry setting **both** to different values is now **refused at load** rather than guessed.
- `src/tenants.json` carries a `THREE_SEPARATE_IDENTITIES` block spelling out that the
  publishing account (signs, issues nothing), `tokens[].issuer` (issues, signs nothing) and
  `tokens[].contract` (an EVM address, neither) are three values with three roles.

### Changed — the pinned tenant is now `tvvin-sandbox`

- **BREAKING:** the `tvvin` pin is **removed**, not repaired. It named the `(default)`-database
  deployment but had been repointed to staging's ETH token while keeping the token issuer as
  its publishing account, so it could verify a transaction from neither deployment. A pin name
  mapping to trust roots that verify nothing reads as coverage and is worse than no pin.
  `--tenant tvvin` now reports `UNKNOWN_TENANT` with an upgrade hint.
- Added **`tvvin-sandbox`** — the deployment that actually publishes (staging.bipcircle.com →
  `bipcircle-api-test` → `bipcircle-staging`), with the correct publishing account, both GBP-cell
  tokens, and the shared bank-service URL and kid pattern.
- Transactions from the other deployment's anchor wallet (`rat8Bjs…`, e.g. `7753CF92…`) **FAIL**
  the account check under this registry. That is correct: they are not `tvvin-sandbox`
  attestations, and they are not made to pass.

### Added — `bipcircleTenantId`, enforced against the witness

`tenantId` in the registry is the **pin name** (what a user types after `--tenant`); the new
`bipcircleTenantId` is the BIPCircle platform tenant id. They are separate fields even when the
strings match, so the public CLI surface and the platform's internal naming can move
independently.

It is load-bearing, not documentation: **the witness file's `tenantId` must equal it**
(`WITNESS_TENANT_MISMATCH` → FAIL). Memo 5 carries no tenant identifier, and there is exactly
one bank-service and one signing key today, so the kid pattern cannot tell two deployments
apart. Without this check, one deployment's reserve evidence could back another's transaction.

### Fixed — a check that could not RUN no longer reports as a reserve failure

A verifier that says FAIL for "you forgot a flag" teaches people to ignore FAIL. Two cases that
reported as supply-stage failures are now `INCONCLUSIVE` (still never PASS, still a non-zero
exit, but honestly attributed):

- **`ETH_RPC_URL_NOT_SUPPLIED`** — an EVM token with no `--eth-rpc-url`. Previously surfaced as
  `RESERVE_SHORTFALL`-adjacent noise in the failures list.
- **`XRPL_SUPPLY_PRECISION_UNPINNED`** — the ledger reports more fractional digits than the
  registry pins for an XRPL token. This was live: TVV was pinned at `decimals: 0` against real
  obligations of `2191947.52`, so the first real run would have reported a raw
  `decimalStringToMinorUnits` error as a reserve verdict. TVV is now pinned at `6`, and the
  registry documents `decimals` as a precision ceiling rather than a display preference.
- A pinned entry with **no** publishing account now reports `REGISTRY_ENTRY_INCOMPLETE` (a defect
  in this file) instead of rejecting every transaction with `XRPL_ACCOUNT_MISMATCH` — blaming the
  transaction for a hole in the registry.

### Added — a published drift verdict is headlined

`out_of_tolerance` and `partial_drift` already produced a `FAIL`. The rendered report now says so
on the verdict line: *"the issuer's own anchored record declares 'out_of_tolerance' — this
transaction is evidence of a DETECTED RESERVE DISCREPANCY, not of backing … (that is a published
attestation of drift, not a verifier malfunction)"*. The independent reserve comparison still runs;
the disclosure never short-circuits it.

### Internal

- `tenantRegistry.js` — the real loader and the test helper `_setForTests` now share **one**
  `normaliseTenant`. They previously carried separate copies, so a fixture could be accepted in a
  shape the shipped loader would reject.
- `test/registryIdentity.test.js` — 20 tests pinning the identity separation itself, not just the
  corrected values: a transaction signed by the token issuer is still rejected, the shipped
  registry's publishing account is asserted to differ from every issuer and contract, the witness
  binding follows `bipcircleTenantId` rather than the pin name, and no XRPL token may be pinned
  below 2 decimal places.

### Verified against real artefacts

Not only fixtures: the full chain was re-derived against the live published witness
`https://storage.googleapis.com/bipcircle-verifier-witnesses-testnet/tvvin/2026-05-25.json`, the
live bank-service JWKS, real ECDSA verification of both seals, the real Merkle root, a real Sepolia
`totalSupply()` (983,055 TVETH) and real XRPL `gateway_balances` (2,191,947.52 TVV) against a real
£0.00 sealed bank reserve — a correctly reported £3,175,002.52 shortfall.

---

## [0.6.0] — 2026-07-29 *(never published to npm)*

**BREAKING:** the verdict is bound to the currency cell the transaction attests.

- **Memo 1 is consumed.** `src/xrpl.js` always extracted the canonical `treasury-attestation-v1`
  record; nothing read it. Before 0.6.0 a GBP-cell tx and an EUR-cell tx returned **byte-identical**
  results, both driven by whichever cell `tenants.json` listed first. The supply stage and verdict
  are now scoped to the cell the record names (`stages.supply.verifiedCell`, `stages.record`).
- Producer/registry disagreement about a token's cell is a loud `CELL_BINDING_MISMATCH` FAIL,
  never a silent re-scope.
- A **published verdict** other than `balanced` is surfaced: drift (`out_of_tolerance`,
  `partial_drift`) → FAIL; incomplete coverage (`partial_balanced`, `provider_unavailable`) →
  INCONCLUSIVE.
- Canonical record versions v1 and v2 both parse. A v1 record's `bank`/`delta` are the literal
  `'null'` (a producer defect affecting every record anchored 2026-05-23…2026-07-29); `null` means
  "never committed" and is never coerced to `0`.
- `combined` cross-chain rows are labelled and verified as the whole cell.
- The record's claimed figures are **never** inputs to the PASS/FAIL comparison.

## [0.5.0] — 2026-07-29 *(never published to npm)*

**BREAKING:** each currency cell is verified against its own reserves.

- The issuer is a protected cell company: cells are legally segregated and never net. Pre-0.5.0
  summed all tokens' supplies into one pot against one currency's reserves, so a EUR surplus could
  silently cover a GBP shortfall.
- Introduced `reserveCurrency` per token (registry schema v3) and the `INCONCLUSIVE` verdict — a
  check that did not run is never reported as one that passed.
- Fixed a `RangeError` (negative BigInt exponent) when a cell's first token had fewer decimals than
  a sibling.

## [0.4.0] — 2026-07-07 *(npm `latest`)*

- `POR-RESERVE-DOUBLECOUNT-01` — dedup balance seals per account; filter to the reserves currency.
- `POR-MERKLE-V1-MALLEABLE-02` — RFC-6962 domain-separated Merkle root for v2 witnesses, dispatched
  on the witness's declared `protocolVersion`; published v1 witnesses still verify.
- `POR-SEAL-FRESHNESS-01` — gate summed seals to the witness date and the `/v1/balance` endpoint,
  closing attest-then-drain-then-replay.

## [0.3.x] — 2026-06-16

- Hosted browser verifier under `docs/`; formatted treasury balances and XRPL account links.

## [0.1.x] — 2026-05-24

- Initial open-source verifier for public-reserve-verifier protocol v1; pinned tenant registry
  closing audit findings F1 (user-supplied bank-service URL) and F2 (attestation accepted from any
  account).
