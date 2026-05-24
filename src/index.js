/**
 * index.js — programmatic entry point. The CLI in bin/ thin-wraps this.
 *
 * The orchestration shape:
 *
 *   1. fetchAttestationTx(txHash) — pull the XRPL transaction +
 *      decode the verifier-protocol memo.
 *   2. fetchAndValidateWitness(witnessUrl, sha256, merkleRoot) —
 *      pull the witness file, validate SHA-256 + claimed Merkle
 *      root + schema.
 *   3. fetchJwks(bankServiceUrl) — pull the bank-service public-key
 *      set. (URL must be supplied by the operator OR derived from
 *      the witness's bankServicePublicKeyId prefix — neither is
 *      currently on-chain so the verifier needs an explicit
 *      --bank-service-url flag.)
 *   4. verifySealSignatures — ECDSA-verify every seal in the
 *      witness against the JWKS. Compute leaf digests.
 *   5. computeMerkleRoot — rebuild the root from leaves; compare
 *      to the witness's claimed root.
 *   6. (optional) on-chain supply check.
 *
 * Returns a structured result. PASS iff every step succeeds.
 */

'use strict';

import { fetchAttestationTx } from './xrpl.js';
import { fetchAndValidateWitness } from './witness.js';
import { fetchJwks } from './keys.js';
import { verifySealSignatures } from './sigverify.js';
import { computeMerkleRoot } from './merkle.js';

export async function verify({
  txHash,
  network = 'mainnet',
  bankServiceUrl,
  rpcUrl,
  fetchImpl = fetch,
}) {
  const result = {
    verdict: 'PENDING',
    stages: {},
    failures: [],
  };

  // Stage 1: XRPL tx + memo
  let txResult;
  try {
    txResult = await fetchAttestationTx({ txHash, network, rpcUrl, fetchImpl });
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
    result.failures.push({ stage: 'xrpl', reason: `Memo 5 missing required fields (sealMerkleRoot/witnessSha256/witnessUrl)` });
    result.verdict = 'FAIL';
    return result;
  }

  // Stage 2: witness fetch + SHA-256 + claimed Merkle root
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

  // Stage 3: JWKS
  if (!bankServiceUrl) {
    result.failures.push({ stage: 'jwks', reason: 'bankServiceUrl is required to fetch the JWKS — pass --bank-service-url' });
    result.verdict = 'FAIL';
    return result;
  }
  let jwksByKid;
  try {
    jwksByKid = await fetchJwks({ bankServiceUrl, fetchImpl });
    result.stages.jwks = { ok: true, keyCount: jwksByKid.size, kids: [...jwksByKid.keys()] };
  } catch (err) {
    result.failures.push({ stage: 'jwks', reason: err.message });
    result.verdict = 'FAIL';
    return result;
  }

  // Stage 4 + 5: ECDSA + Merkle
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
      reason: `Merkle root mismatch — witness leaves don't reproduce the anchored root. claimed=${memo.sealMerkleRoot} derived=${derivedRoot}`,
    });
  }
  if (!result.stages.signatures.ok) {
    result.failures.push({
      stage: 'signatures',
      reason: `${sigFailures.length} of ${sigResults.length} seal signatures failed verification`,
      details: sigFailures,
    });
  }

  result.verdict = result.failures.length === 0 ? 'PASS' : 'FAIL';
  return result;
}
