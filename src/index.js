/**
 * index.js — programmatic entry point. The CLI in bin/ thin-wraps this.
 *
 * Two operating modes:
 *
 *   1. REGISTERED-TENANT mode (preferred): pass `tenantId` whose entry
 *      lives in src/tenants.json. The verifier loads the pinned
 *      bankServiceUrl + xrplIssuerAddress + kidPattern + token config
 *      from the registry. Trust roots come from the verifier source
 *      release, NOT user input — this closes Pro audit F1+F2 (user-
 *      supplied URL / TX-from-any-account spoofing).
 *
 *   2. UNSAFE-OVERRIDE mode: pass `bankServiceUrl` + `xrplIssuerAddress`
 *      explicitly. Useful for ad-hoc verification of unregistered
 *      tenants OR newly-added tenants whose entry hasn't shipped in
 *      the verifier yet. Operator-explicit risk.
 *
 * Pipeline:
 *
 *   1. fetchAttestationTx(txHash) — pull XRPL tx + decode Memo 5.
 *      Validate tx.Account === xrplIssuerAddress. (F2 fix.)
 *   2. fetchAndValidateWitness — pull witness JSON, validate SHA-256
 *      + claimed Merkle root + schema.
 *   3. fetchJwks(bankServiceUrl) — pull bank-service JWKS. Validate
 *      that the kid in seal.publicKeyId matches the tenant's
 *      kidPattern. (F1 fix.)
 *   4. verifySealSignatures — ECDSA-verify each seal.
 *   5. computeMerkleRoot — rebuild root from leaves; compare to
 *      witness's claimed root.
 *   6. On-chain supply comparison, per currency cell (v0.5.0 — the
 *      issuer is a protected cell company; each cell holds one fiat
 *      currency and is legally segregated, so every cell is verified
 *      against ONLY its own currency's bank reserves).
 *
 * Returns a structured PASS / FAIL / INCONCLUSIVE with per-stage diff.
 * INCONCLUSIVE (v0.5.0) means at least one check could not be performed
 * (skipped stage, missing token config, unresolvable cell currency) —
 * a verifier must never say PASS for a check it did not run.
 */

'use strict';

import { fetchAttestationTx } from './xrpl.js';
import { fetchAndValidateWitness } from './witness.js';
import { fetchJwks } from './keys.js';
import { verifySealSignatures } from './sigverify.js';
import { computeMerkleRootForVersion } from './merkle.js';
import { lookupTenant } from './tenantRegistry.js';
import {
  getEthereumErc20TotalSupply,
  getXrplIssuedSupply,
  sumBankReservesDetailed,
  compareReservesVsSupply,
  decimalStringToMinorUnits,
} from './onchain.js';

/**
 * Resolve the fiat currency of the CELL a token belongs to.
 *
 * The issuer is a protected cell company: each cell holds exactly one fiat
 * currency and is legally segregated, so the cell currency is the boundary
 * every reserve comparison must respect.
 *
 *   - `reserveCurrency` (explicit, preferred — registry schema v3)
 *   - legacy fallback: for ethereum tokens, `currency` has always been the
 *     fiat denomination (e.g. 'GBP'), so it is a safe cell key
 *   - XRPL tokens' `currency` is the ON-LEDGER TICKER (e.g. 'TVV'), never a
 *     fiat currency — no fallback. Missing reserveCurrency on an XRPL token
 *     resolves to null and the verdict becomes INCONCLUSIVE (fail-closed):
 *     an unassignable token must never silently vanish from the liability.
 *
 * @returns {string|null}
 */
function resolveCellCurrency(tok) {
  if (typeof tok.reserveCurrency === 'string' && tok.reserveCurrency.trim().length > 0) {
    return tok.reserveCurrency.trim();
  }
  if (tok.chain === 'ethereum' && typeof tok.currency === 'string' && tok.currency.trim().length > 0) {
    return tok.currency.trim();
  }
  return null;
}

export async function verify({
  txHash,
  tenantId,
  bankServiceUrl: unsafeBankServiceUrl,
  xrplIssuerAddress: unsafeIssuer,
  network = 'mainnet',
  rpcUrl,
  ethRpcUrl,
  fetchImpl = fetch,
  skipOnChainSupply = false,
}) {
  const result = {
    verdict: 'PENDING',
    mode: null,
    stages: {},
    failures: [],
    // v0.5.0: checks that could NOT be performed. A non-empty list means the
    // verdict can never be PASS — it becomes INCONCLUSIVE (unless something
    // else already made it FAIL). A verifier must never say PASS for a check
    // it did not run.
    inconclusive: [],
  };

  // Resolve trust roots from the tenant registry OR explicit override.
  let trustRoots;
  if (tenantId) {
    const t = lookupTenant(tenantId);
    if (!t) {
      result.failures.push({
        stage: 'registry',
        reason: `UNKNOWN_TENANT: '${tenantId}' is not in this verifier's pinned registry. Upgrade to a newer version of bipcircle-verifier OR re-run with --unsafe-bank-service-url + --unsafe-issuer (operator-explicit risk).`,
      });
      result.verdict = 'FAIL';
      return result;
    }
    trustRoots = {
      bankServiceUrl: t.bankServiceUrl,
      xrplIssuerAddress: t.xrplIssuerAddress,
      kidRegex: t._kidRegex,
      // v2 registry shape: tokens[] (multi-chain). tenantRegistry.js
      // back-compat-maps the old single `token` to a 1-element array
      // so reads here always see an array.
      tokens: Array.isArray(t.tokens) ? t.tokens : [],
    };
    result.mode = 'registered-tenant';
    result.stages.registry = { ok: true, tenantId, source: 'pinned', tokenCount: trustRoots.tokens.length };
  } else {
    if (!unsafeBankServiceUrl || !unsafeIssuer) {
      result.failures.push({
        stage: 'registry',
        reason: 'Either --tenant <id> (preferred) OR (--unsafe-bank-service-url AND --unsafe-issuer) must be supplied',
      });
      result.verdict = 'FAIL';
      return result;
    }
    trustRoots = {
      bankServiceUrl: unsafeBankServiceUrl,
      xrplIssuerAddress: unsafeIssuer,
      kidRegex: null,
      tokens: [],
    };
    result.mode = 'unsafe-override';
    result.stages.registry = { ok: true, source: 'unsafe-override', tokenCount: 0 };
  }

  // Stage 1: XRPL tx + Memo 5 + Account binding
  let txResult;
  try {
    txResult = await fetchAttestationTx({ txHash, network, rpcUrl, fetchImpl });
    if (txResult.account !== trustRoots.xrplIssuerAddress) {
      throw new Error(
        `XRPL_ACCOUNT_MISMATCH: tx ${txHash} was published by '${txResult.account}' but the trust root expects '${trustRoots.xrplIssuerAddress}'. ` +
        `This tx is not a legitimate ${tenantId || 'unsafe-override'} attestation.`,
      );
    }
    result.stages.xrpl = {
      ok: true,
      txHash,
      ledgerIndex: txResult.ledgerIndex,
      account: txResult.account,
      memo: txResult.verifierMemo,
    };
  } catch (err) {
    result.failures.push({ stage: 'xrpl', reason: err.message });
    result.verdict = 'FAIL';
    return result;
  }

  const memo = txResult.verifierMemo;
  if (!memo.sealMerkleRoot || !memo.witnessSha256 || !memo.witnessUrl) {
    result.failures.push({ stage: 'xrpl', reason: 'Memo 5 missing required fields (sealMerkleRoot/witnessSha256/witnessUrl)' });
    result.verdict = 'FAIL';
    return result;
  }
  if (trustRoots.kidRegex && memo.bankServicePublicKeyId && !trustRoots.kidRegex.test(memo.bankServicePublicKeyId)) {
    result.failures.push({
      stage: 'xrpl',
      reason: `MEMO_KID_MISMATCH: Memo 5 references bankServicePublicKeyId='${memo.bankServicePublicKeyId}' which does not match the tenant's pinned kidPattern. Possible attacker-controlled tx.`,
    });
    result.verdict = 'FAIL';
    return result;
  }

  // Stage 2: witness
  let witness;
  try {
    witness = await fetchAndValidateWitness({
      witnessUrl: memo.witnessUrl,
      expectedWitnessSha256: memo.witnessSha256,
      expectedMerkleRoot: memo.sealMerkleRoot,
      fetchImpl,
    });
    result.stages.witness = {
      ok: true,
      asOfDate: witness.asOfDate,
      tenantId: witness.tenantId,
      sealCount: witness.sealCount,
    };
  } catch (err) {
    result.failures.push({ stage: 'witness', reason: err.message });
    result.verdict = 'FAIL';
    return result;
  }

  // Stage 3: JWKS + kid pattern binding
  let jwksByKid;
  try {
    jwksByKid = await fetchJwks({ bankServiceUrl: trustRoots.bankServiceUrl, fetchImpl });
    if (trustRoots.kidRegex) {
      for (const kid of jwksByKid.keys()) {
        if (!trustRoots.kidRegex.test(kid)) {
          throw new Error(
            `JWKS_KID_PATTERN_MISMATCH: JWKS advertised kid '${kid}' that does not match the tenant's pinned pattern. ` +
            `Refusing to trust this JWKS — possible attacker-controlled bank-service URL.`,
          );
        }
      }
    }
    result.stages.jwks = { ok: true, keyCount: jwksByKid.size, kids: [...jwksByKid.keys()] };
  } catch (err) {
    result.failures.push({ stage: 'jwks', reason: err.message });
    result.verdict = 'FAIL';
    return result;
  }

  // Stages 4+5: ECDSA + Merkle
  const { results: sigResults, leaves } = verifySealSignatures({
    witnessSeals: witness.seals,
    jwksByKid,
  });
  const sigFailures = sigResults.filter((r) => !r.ok);
  result.stages.signatures = {
    ok: sigFailures.length === 0,
    sealsVerified: sigResults.filter((r) => r.ok).length,
    sealsTotal: sigResults.length,
    failures: sigFailures,
  };

  // POR-MERKLE-V1-MALLEABLE-02: dispatch the Merkle algorithm on the witness's
  // declared protocolVersion. v2 witnesses use the RFC-6962 domain-separated
  // root (non-malleable); already-published v1 witnesses still verify with v1.
  const derivedRoot = computeMerkleRootForVersion(leaves, witness.protocolVersion);
  result.stages.merkle = {
    ok: derivedRoot === memo.sealMerkleRoot,
    claimed: memo.sealMerkleRoot,
    derived: derivedRoot,
    protocolVersion: witness.protocolVersion || 'v1',
  };
  if (!result.stages.merkle.ok) {
    result.failures.push({
      stage: 'merkle',
      reason: `Merkle root mismatch — claimed=${memo.sealMerkleRoot} derived=${derivedRoot}`,
    });
  }
  if (!result.stages.signatures.ok) {
    result.failures.push({
      stage: 'signatures',
      reason: `${sigFailures.length} of ${sigResults.length} seal signatures failed verification`,
      details: sigFailures,
    });
  }

  // Stage 6: on-chain supply comparison — PER CURRENCY CELL (v0.5.0).
  //
  // The issuer is a protected cell company. Each cell holds ONE fiat currency
  // and is legally segregated: cell A's surplus can never cover cell B's
  // shortfall — that segregation is the point of the structure, and checking
  // it is why this tool exists. Tokens are therefore grouped by their cell
  // currency (resolveCellCurrency) and EVERY cell is verified against ONLY
  // its own currency's bank reserves. Pre-0.5.0 releases summed all tokens'
  // supplies into one pot and compared it against one currency's reserves —
  // a EUR surplus could silently pay for a GBP shortfall.
  //
  // The verdict can never become PASS through absence:
  //   - --skip-onchain            → INCONCLUSIVE, never PASS
  //   - zero tokens configured    → INCONCLUSIVE (registry gap ≠ verified)
  //   - unsafe-override mode      → INCONCLUSIVE (no pinned token config)
  //   - unresolvable cell currency→ INCONCLUSIVE (token can't vanish silently)
  // A genuine reserve shortfall in ANY cell → FAIL.
  if (skipOnChainSupply) {
    result.stages.supply = { ok: null, skipped: true, reason: 'skipped by flag (--skip-onchain)' };
    result.inconclusive.push({
      stage: 'supply',
      reason: 'SUPPLY_CHECK_SKIPPED: the on-chain supply vs bank-reserve comparison was skipped (--skip-onchain). Reserve backing was NOT verified, so the verdict cannot be PASS.',
    });
  } else if (trustRoots.tokens.length === 0) {
    result.stages.supply = {
      ok: null,
      skipped: true,
      reason: result.mode === 'unsafe-override'
        ? 'unsafe-override mode has no pinned token config'
        : 'no tokens configured for this tenant in the pinned registry',
    };
    result.inconclusive.push({
      stage: 'supply',
      reason: 'SUPPLY_CHECK_NOT_RUN: no token configuration was available, so the reserve backing of the on-chain supply was NOT verified. A missing registry entry must not read as a verified reserve.',
    });
  } else {
    // Group tokens into currency cells. A token whose cell currency cannot
    // be resolved is surfaced as INCONCLUSIVE — it must not be silently
    // dropped from the liability, and it must not be guessed into a cell.
    const cellsByCurrency = new Map();
    for (const tok of trustRoots.tokens) {
      const cellCurrency = resolveCellCurrency(tok);
      if (!cellCurrency) {
        result.inconclusive.push({
          stage: 'supply',
          reason: `CELL_CURRENCY_UNRESOLVED: token '${tok.label || `${tok.currency}-${tok.chain}`}' has no reserveCurrency (and no legacy fiat fallback), so its liability could not be assigned to a currency cell and was NOT verified.`,
        });
        continue;
      }
      if (!cellsByCurrency.has(cellCurrency)) cellsByCurrency.set(cellCurrency, []);
      cellsByCurrency.get(cellCurrency).push(tok);
    }

    const cells = [];
    for (const [cellCurrency, cellTokens] of cellsByCurrency) {
      try {
        const badDecimals = cellTokens.find(
          (t) => !Number.isInteger(t.decimals) || t.decimals < 0 || t.decimals > 18,
        );
        if (badDecimals) {
          result.inconclusive.push({
            stage: 'supply',
            reason: `CELL_CONFIG_INVALID[${cellCurrency}]: token '${badDecimals.label || badDecimals.contract || badDecimals.issuer}' has invalid decimals (${JSON.stringify(badDecimals.decimals)}); the ${cellCurrency} cell was NOT verified.`,
          });
          continue;
        }
        // Cell decimals = the max across the cell's tokens, so every rebase
        // multiplies UP (exponent >= 0). Pre-0.5.0 used the first ethereum
        // token's decimals as the base, which threw RangeError (negative
        // BigInt exponent) whenever the base had fewer decimals than a
        // sibling token.
        const cellDecimals = Math.max(...cellTokens.map((t) => t.decimals));

        // POR-RESERVE-DOUBLECOUNT-01 + POR-SEAL-FRESHNESS-01 gates unchanged;
        // the currency filter is now ALWAYS a non-empty cell currency, so a
        // missing registry field can no longer switch the filter off.
        const reserves = sumBankReservesDetailed(witness.seals, cellDecimals, cellCurrency, {
          asOfDate: witness.asOfDate,
          maxSealAgeHours: 48,
          expectedEndpoint: '/v1/balance',
        });

        const perToken = [];
        let cellSupplyMinor = 0n;
        for (const tok of cellTokens) {
          let supplyMinor;
          if (tok.chain === 'ethereum') {
            if (!ethRpcUrl) {
              throw new Error('ethRpcUrl required for ethereum-chain on-chain check (pass --eth-rpc-url)');
            }
            supplyMinor = await getEthereumErc20TotalSupply({
              rpcUrl: ethRpcUrl,
              contractAddress: tok.contract,
              fetchImpl,
            });
          } else if (tok.chain === 'xrpl') {
            const xrplRpc = rpcUrl || (network === 'mainnet'
              ? 'https://s1.ripple.com:51234/'
              : 'https://s.altnet.rippletest.net:51234/');
            const supplyStr = await getXrplIssuedSupply({
              rpcUrl: xrplRpc,
              issuerAddress: tok.issuer,
              currencyCode: tok.currency,
              fetchImpl,
            });
            supplyMinor = decimalStringToMinorUnits(supplyStr, tok.decimals);
          } else {
            throw new Error(`unknown chain '${tok.chain}' in tenant registry`);
          }
          // Rebase to the cell decimals — exponent is provably >= 0.
          const rebased = tok.decimals === cellDecimals
            ? supplyMinor
            : supplyMinor * (10n ** BigInt(cellDecimals - tok.decimals));
          perToken.push({
            label: tok.label || `${tok.currency}-${tok.chain}`,
            chain: tok.chain,
            currency: tok.currency,
            cellCurrency,
            decimals: tok.decimals,
            issuer: tok.issuer ?? null,     // XRPL issuer account (its obligations = the on-ledger balance)
            contract: tok.contract ?? null, // ETH token contract
            supplyMinor: supplyMinor.toString(),
            rebasedToCellMinor: rebased.toString(),
          });
          cellSupplyMinor += rebased;
        }

        // Tolerance is a CELL property and never crosses a cell boundary.
        // Declared per-token values are interpreted at the declaring token's
        // decimals, rebased to the cell decimals; if several tokens in one
        // cell declare different values the STRICTEST (smallest) wins — a
        // registry mistake must never widen the tolerance.
        const declaredTolerances = cellTokens
          .filter((t) => t.toleranceMinorUnits !== undefined && t.toleranceMinorUnits !== null)
          .map((t) => BigInt(t.toleranceMinorUnits) * (10n ** BigInt(cellDecimals - t.decimals)));
        const tolerance = declaredTolerances.length > 0
          ? declaredTolerances.reduce((a, b) => (b < a ? b : a))
          : 0n;

        const cmp = compareReservesVsSupply({
          reservesMinorUnits: reserves.totalMinorUnits,
          onChainSupplyMinorUnits: cellSupplyMinor,
          toleranceMinorUnits: tolerance,
        });
        cells.push({
          currency: cellCurrency,
          decimals: cellDecimals,
          ok: cmp.ok,
          ...cmp,
          toleranceMinorUnits: tolerance.toString(),
          reserveAccountCount: reserves.accountCount,
          reserveSealCount: reserves.matchedSealCount,
          perToken,
        });
        if (!cmp.ok) {
          const noEvidence = reserves.accountCount === 0
            ? ' No balance seal for this currency appears in the witness — either a genuine zero reserve or missing evidence; both must FAIL.'
            : '';
          result.failures.push({
            stage: 'supply',
            reason: `RESERVE_SHORTFALL[${cellCurrency}]: reserves=${cmp.reservesMinorUnits} < on-chain supply=${cmp.onChainSupplyMinorUnits} for the ${cellCurrency} cell (shortfall=${cmp.shortfallMinorUnits} minor units at ${cellDecimals}dp). Cells are legally segregated — no other currency's surplus can cover this.${noEvidence}`,
          });
        }
      } catch (err) {
        result.failures.push({ stage: 'supply', reason: `[cell ${cellCurrency}] ${err.message}` });
      }
    }

    const anyCellFailed = result.failures.some((f) => f.stage === 'supply');
    const anyCellInconclusive = result.inconclusive.some((f) => f.stage === 'supply');
    result.stages.supply = {
      ok: anyCellFailed ? false : (anyCellInconclusive ? null : true),
      cellCount: cells.length,
      tokenCount: trustRoots.tokens.length,
      cells,
    };
  }

  // Verdict precedence: any failure → FAIL; else any unperformed check →
  // INCONCLUSIVE; only a fully-executed, fully-clean run → PASS.
  if (result.failures.length > 0) {
    result.verdict = 'FAIL';
  } else if (result.inconclusive.length > 0) {
    result.verdict = 'INCONCLUSIVE';
  } else {
    result.verdict = 'PASS';
  }
  return result;
}
