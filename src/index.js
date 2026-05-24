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
 *   6. On-chain supply comparison (v0.1.2 — wired in via the
 *      tenant registry's token config).
 *
 * Returns a structured PASS / FAIL with per-stage diff.
 */

'use strict';

import { fetchAttestationTx } from './xrpl.js';
import { fetchAndValidateWitness } from './witness.js';
import { fetchJwks } from './keys.js';
import { verifySealSignatures } from './sigverify.js';
import { computeMerkleRoot } from './merkle.js';
import { lookupTenant } from './tenantRegistry.js';
import {
  getEthereumErc20TotalSupply,
  getXrplIssuedSupply,
  sumBankReserves,
  compareReservesVsSupply,
  decimalStringToMinorUnits,
} from './onchain.js';

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
      token: t.token || null,
    };
    result.mode = 'registered-tenant';
    result.stages.registry = { ok: true, tenantId, source: 'pinned' };
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
      token: null,
    };
    result.mode = 'unsafe-override';
    result.stages.registry = { ok: true, source: 'unsafe-override' };
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

  const derivedRoot = computeMerkleRoot(leaves);
  result.stages.merkle = {
    ok: derivedRoot === memo.sealMerkleRoot,
    claimed: memo.sealMerkleRoot,
    derived: derivedRoot,
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

  // Stage 6: on-chain supply comparison (v0.1.2 wires in 0.2.0 primitive)
  if (!skipOnChainSupply && trustRoots.token) {
    try {
      const reservesMinor = sumBankReserves(witness.seals, trustRoots.token.decimals);
      let supplyMinor;
      if (trustRoots.token.chain === 'ethereum') {
        if (!ethRpcUrl) {
          throw new Error('ethRpcUrl required for ethereum-chain on-chain check (pass --eth-rpc-url)');
        }
        supplyMinor = await getEthereumErc20TotalSupply({
          rpcUrl: ethRpcUrl,
          contractAddress: trustRoots.token.contract,
          fetchImpl,
        });
      } else if (trustRoots.token.chain === 'xrpl') {
        const xrplRpc = rpcUrl || (network === 'mainnet'
          ? 'https://s1.ripple.com:51234/'
          : 'https://s.altnet.rippletest.net:51234/');
        const supplyStr = await getXrplIssuedSupply({
          rpcUrl: xrplRpc,
          issuerAddress: trustRoots.token.issuer,
          currencyCode: trustRoots.token.currency,
          fetchImpl,
        });
        supplyMinor = decimalStringToMinorUnits(supplyStr, trustRoots.token.decimals);
      } else {
        throw new Error(`unknown chain '${trustRoots.token.chain}' in tenant registry`);
      }
      const tolerance = trustRoots.token.toleranceMinorUnits
        ? BigInt(trustRoots.token.toleranceMinorUnits)
        : 0n;
      const cmp = compareReservesVsSupply({
        reservesMinorUnits: reservesMinor,
        onChainSupplyMinorUnits: supplyMinor,
        toleranceMinorUnits: tolerance,
      });
      result.stages.supply = { ok: cmp.ok, ...cmp, chain: trustRoots.token.chain };
      if (!cmp.ok) {
        result.failures.push({
          stage: 'supply',
          reason: `RESERVE_SHORTFALL: reserves=${cmp.reservesMinorUnits} < supply=${cmp.onChainSupplyMinorUnits} (shortfall=${cmp.shortfallMinorUnits} minor units)`,
        });
      }
    } catch (err) {
      result.failures.push({ stage: 'supply', reason: err.message });
    }
  } else if (skipOnChainSupply || !trustRoots.token) {
    result.stages.supply = { ok: null, skipped: true, reason: skipOnChainSupply ? 'flag' : 'no token config in registry / unsafe-override mode' };
  }

  result.verdict = result.failures.length === 0 ? 'PASS' : 'FAIL';
  return result;
}
