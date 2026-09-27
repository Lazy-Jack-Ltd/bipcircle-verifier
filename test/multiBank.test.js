/**
 * multiBank.test.js — registry schema v5: a pin lists several bank services,
 * each with its own URL and kidPattern, and a seal verifies against the bank
 * service whose kid it carries.
 *
 * No network: every fetch is stubbed. Two fixture banks, A and B, each with
 * its own keypair and JWKS; each signs one GBP balance seal for a different
 * provider, so the reserve (1,200) only covers the 1,000 TVV supply when BOTH
 * seals verify and are summed.
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

import { buildCanonicalInput } from '../src/canonical.js';
import { computeMerkleRoot, leafDigest } from '../src/merkle.js';
import { verify } from '../src/index.js';
import {
  _setForTests as setRegistryForTests,
  _resetForTests as resetRegistry,
  lookupTenant,
  resolveBankServiceForKid,
} from '../src/tenantRegistry.js';

const TENANT = 'multi-bank';
const DATE = '2026-09-27';
const TXHASH = 'A'.repeat(64);
const ISSUER = 'rExampleIssuerAddress0000000000000000000';
const WITNESS_URL = `https://storage.googleapis.com/witnesses/${TENANT}/${DATE}.json`;
const BANK_A = { url: 'https://bank-service-a.example', kid: 'keys/bank-a/1', kidPattern: '^keys/bank-a/\\d+$' };
const BANK_B = { url: 'https://bank-service-b.example', kid: 'keys/bank-b/1', kidPattern: '^keys/bank-b/\\d+$' };
const TOKENS = [{ label: 'TVV', chain: 'xrpl', issuer: ISSUER, currency: 'TVV', decimals: 2, reserveCurrency: 'GBP' }];
const RECORD = `v1|${DATE}|xrpl-testnet|gbp.${ISSUER}|GBP|balanced|1000.00|1000.00|null|null|${DATE}_${TENANT}_xrpl-testnet_gbp.${ISSUER}`;

const jwkOf = (publicKey, kid) => {
  const j = publicKey.export({ format: 'jwk' });
  return { kty: 'EC', crv: 'P-256', x: j.x, y: j.y, use: 'sig', alg: 'ES256', kid };
};

/**
 * @param {object} o
 * @param {Array<{bank, kid?, signWith?}>} [o.seals] which bank signs each seal (kid defaults to the bank's)
 * @param {Record<string, object[]>} [o.extraJwks] extra JWKs appended to a bank's JWKS, by bank url
 * @param {Set<string>} [o.down] bank urls whose JWKS endpoint fails
 */
function world({ seals = [{ bank: BANK_A }, { bank: BANK_B }], extraJwks = {}, down = new Set(), memoKid } = {}) {
  const keys = new Map([BANK_A, BANK_B].map((b) => [b.url, crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })]));
  const witnessSeals = [];
  const leaves = [];
  seals.forEach((s, i) => {
    const eventId = `00000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}`;
    const signedAt = `${DATE}T10:00:0${i + 1}.000Z`;
    const payload = { type: 'balance', provider: `provider-${i}`, currency: 'GBP', availableBalance: '600.00', asOf: signedAt };
    const bytes = Buffer.from(buildCanonicalInput({ payload, tenantId: TENANT, eventId, signedAt, endpoint: '/v1/balance' }), 'utf8');
    const signer = s.signWith || keys.get(s.bank.url).privateKey;
    witnessSeals.push({
      eventId, signedAt,
      canonicalInput: bytes.toString('base64'),
      signature: crypto.sign('sha256', bytes, { key: signer, dsaEncoding: 'der' }).toString('base64'),
      publicKeyId: s.kid || s.bank.kid,
    });
    leaves.push(leafDigest(bytes));
  });
  const sealMerkleRoot = computeMerkleRoot(leaves);
  const witnessJson = JSON.stringify({
    protocolVersion: 'v1', asOfDate: DATE, tenantId: TENANT,
    bankServicePublicKeyId: witnessSeals[0].publicKeyId, sealMerkleRoot, sealCount: witnessSeals.length, seals: witnessSeals,
  });
  const witnessSha256 = crypto.createHash('sha256').update(witnessJson, 'utf8').digest('hex');
  const memo5 = {
    protocolVersion: 'v1', sealMerkleRoot, witnessSha256,
    bankServicePublicKeyId: memoKid || witnessSeals[0].publicKeyId, sealCount: witnessSeals.length, witnessUrl: WITNESS_URL,
  };
  const hex = (x) => Buffer.from(x, 'utf8').toString('hex').toUpperCase();
  const xrplTx = { result: { Account: ISSUER, ledger_index: 1, Memos: [
    { Memo: { MemoType: hex('treasury-attestation-v1'), MemoData: hex(RECORD) } },
    { Memo: { MemoType: hex('reserve-verifier-v1'), MemoData: hex(JSON.stringify(memo5)) } },
  ] } };
  const jwksFetched = [];
  const fetchImpl = async (url, opts) => {
    if (typeof url === 'string' && url.endsWith('/.well-known/bank-service-keys')) {
      const base = url.replace('/.well-known/bank-service-keys', '');
      jwksFetched.push(base);
      if (down.has(base)) return { ok: false, status: 503 };
      const bank = [BANK_A, BANK_B].find((b) => b.url === base);
      const own = bank ? [jwkOf(keys.get(base).publicKey, bank.kid)] : [];
      return { ok: true, json: async () => ({ keys: [...own, ...(extraJwks[base] || [])] }) };
    }
    if (url === WITNESS_URL) {
      const b = Buffer.from(witnessJson, 'utf8');
      return { ok: true, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) };
    }
    let body = {};
    try { body = JSON.parse(opts?.body || '{}'); } catch { /* not JSON */ }
    if (body.method === 'gateway_balances') return { ok: true, json: async () => ({ result: { obligations: { TVV: '1000' } } }) };
    return { ok: true, json: async () => xrplTx };
  };
  return { fetchImpl, jwksFetched, keys };
}

function pin(bankServices, extra = {}) {
  setRegistryForTests({ tenants: [{ tenantId: TENANT, xrplPublishingAccount: ISSUER, bankServices, tokens: TOKENS, ...extra }] });
}

const run = (w) => verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: w.fetchImpl, network: 'testnet' });
const reasons = (r) => JSON.stringify(r.failures);

beforeEach(() => {
  resetRegistry();
  pin([
    { url: BANK_A.url, kidPattern: BANK_A.kidPattern },
    { url: BANK_B.url, kidPattern: BANK_B.kidPattern },
  ]);
});

describe('multi-bank pin: each seal verifies against its own bank service', () => {
  test('PASS when two banks each sign a seal and both reserves are summed', async () => {
    const w = world();
    const r = await run(w);
    assert.equal(r.verdict, 'PASS', `${reasons(r)} ${JSON.stringify(r.inconclusive)}`);
    assert.equal(r.stages.signatures.sealsVerified, 2);
    assert.deepEqual(r.stages.jwks.services.map((s) => [s.url, s.sealCount]), [[BANK_A.url, 1], [BANK_B.url, 1]]);
  });

  test('FAIL: a bank service advertising another bank\'s kid (with its own key) is refused', async () => {
    // Bank A's JWKS also publishes kid bank-b/1 under an attacker key, and the
    // bank-b seal is signed by that attacker key. Without the per-service
    // pattern check the pooled key set would hold two keys for one kid.
    const attacker = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const w = world({
      seals: [{ bank: BANK_A }, { bank: BANK_B, signWith: attacker.privateKey }],
      extraJwks: { [BANK_A.url]: [jwkOf(attacker.publicKey, BANK_B.kid)] },
    });
    const r = await run(w);
    assert.equal(r.verdict, 'FAIL');
    assert.match(reasons(r), /JWKS_KID_PATTERN_MISMATCH: JWKS at https:\/\/bank-service-a\.example/);
  });

  test('FAIL: a seal whose kid matches no pinned bank service', async () => {
    const w = world({ seals: [{ bank: BANK_A }, { bank: BANK_B, kid: 'keys/bank-c/1' }] });
    const r = await run(w);
    assert.equal(r.verdict, 'FAIL');
    assert.match(reasons(r), /SEAL_KID_NOT_PINNED: seal '[^']+' carries kid 'keys\/bank-c\/1'/);
  });

  test('FAIL: a kid matching two bank services\' patterns is ambiguous, not resolved by order', async () => {
    pin([
      { url: BANK_A.url, kidPattern: '^keys/bank-[ab]/\\d+$' },
      { url: BANK_B.url, kidPattern: BANK_B.kidPattern },
    ]);
    const w = world();
    const r = await run(w);
    assert.equal(r.verdict, 'FAIL');
    assert.match(reasons(r), /MEMO_KID_MISMATCH|SEAL_KID_AMBIGUOUS/);
    // The Memo 5 kid is bank-a/1 (unambiguous), so the seal stage is what fires.
    assert.match(reasons(r), /SEAL_KID_AMBIGUOUS: seal '[^']+' carries kid 'keys\/bank-b\/1'/);
  });

  test('FAIL: one kid advertised by two bank services is a collision', async () => {
    // Both patterns admit keys/shared/N; no seal carries it, so seal routing is
    // unambiguous, but both JWKS publish it — one kid, two keys.
    pin([
      { url: BANK_A.url, kidPattern: '^keys/(bank-a|shared)/\\d+$' },
      { url: BANK_B.url, kidPattern: '^keys/(bank-b|shared)/\\d+$' },
    ]);
    const extra = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const w = world({ extraJwks: {
      [BANK_A.url]: [jwkOf(extra.publicKey, 'keys/shared/1')],
      [BANK_B.url]: [jwkOf(extra.publicKey, 'keys/shared/1')],
    } });
    const r = await run(w);
    assert.equal(r.verdict, 'FAIL');
    assert.match(reasons(r), /JWKS_KID_COLLISION: kid 'keys\/shared\/1'/);
  });

  test('only the bank services the witness uses are fetched: bank B down does not fail a bank-A-only day', async () => {
    const w = world({ seals: [{ bank: BANK_A }, { bank: BANK_A }], down: new Set([BANK_B.url]) });
    const r = await run(w);
    assert.equal(r.stages.jwks?.ok, true, reasons(r));
    assert.equal(r.stages.signatures.ok, true);
    assert.deepEqual(w.jwksFetched, [BANK_A.url]);
  });

  test('FAIL: Memo 5 kid that matches no pinned bank service', async () => {
    const w = world({ memoKid: 'keys/bank-c/1' });
    const r = await run(w);
    assert.equal(r.verdict, 'FAIL');
    assert.match(reasons(r), /MEMO_KID_MISMATCH/);
  });
});

describe('registry v5 shape: bankServices[] and the single-URL alias', () => {
  const base = { tenantId: 't', xrplPublishingAccount: ISSUER, tokens: [] };
  const load = (entry) => { setRegistryForTests({ tenants: [{ ...base, ...entry }] }); return lookupTenant('t'); };

  test('the v4 single bankServiceUrl + kidPattern loads as a one-element list', () => {
    const t = load({ bankServiceUrl: BANK_A.url, kidPattern: BANK_A.kidPattern });
    assert.equal(t.bankServices.length, 1);
    assert.equal(t.bankServices[0].url, BANK_A.url);
    assert.equal(resolveBankServiceForKid(t.bankServices, BANK_A.kid).service.url, BANK_A.url);
    assert.equal(resolveBankServiceForKid(t.bankServices, BANK_B.kid).reason, 'not-pinned');
  });

  test('both shapes are accepted when the single pair is one of the listed services', () => {
    const t = load({
      bankServiceUrl: BANK_A.url, kidPattern: BANK_A.kidPattern,
      bankServices: [{ url: BANK_A.url, kidPattern: BANK_A.kidPattern }, { url: BANK_B.url, kidPattern: BANK_B.kidPattern }],
    });
    assert.equal(t.bankServices.length, 2);
  });

  test('both shapes that disagree are refused at load', () => {
    assert.throws(() => load({
      bankServiceUrl: 'https://elsewhere.example', kidPattern: BANK_A.kidPattern,
      bankServices: [{ url: BANK_A.url, kidPattern: BANK_A.kidPattern }],
    }), /disagree about a trust root/);
  });

  test('several services without a kidPattern are refused (a seal could not be attributed)', () => {
    assert.throws(() => load({ bankServices: [{ url: BANK_A.url, kidPattern: BANK_A.kidPattern }, { url: BANK_B.url }] }),
      /has no kidPattern/);
  });

  test('a duplicated bank service url and an empty list are refused', () => {
    assert.throws(() => load({ bankServices: [{ url: BANK_A.url, kidPattern: 'a' }, { url: BANK_A.url, kidPattern: 'b' }] }), /twice/);
    assert.throws(() => load({ bankServices: [] }), /empty bankServices/);
  });

  test('a pinned entry with no bank service FAILs at the registry stage', async () => {
    setRegistryForTests({ tenants: [{ ...base, tenantId: TENANT }] });
    const r = await run(world());
    assert.equal(r.verdict, 'FAIL');
    assert.match(reasons(r), /REGISTRY_ENTRY_INCOMPLETE: pinned tenant 'multi-bank' names no bank service/);
  });
});

describe('shipped tenants.json', () => {
  const shipped = JSON.parse(readFileSync(new URL('../src/tenants.json', import.meta.url), 'utf8'));
  const entry = shipped.tenants.find((t) => t.tenantId === 'tvvin-sandbox');

  test('schema is v5', () => {
    assert.equal(shipped._meta.schemaVersion, 'v5');
  });

  test('tvvin-sandbox is pinned to its own bank service and key, not the shared tvvin signer', () => {
    resetRegistry();
    setRegistryForTests(shipped);
    const t = lookupTenant('tvvin-sandbox');
    assert.deepEqual(t.bankServices.map((s) => s.url), ['https://bank-service-tvvin-sandbox-390262355925.europe-west2.run.app']);
    const own = 'projects/bipcircle/locations/europe-west2/keyRings/bank-service-signers/cryptoKeys/tvvin-sandbox-signer/cryptoKeyVersions/1';
    const shared = 'projects/bipcircle/locations/europe-west2/keyRings/bank-service-signers/cryptoKeys/tvvin-signer/cryptoKeyVersions/1';
    assert.equal(resolveBankServiceForKid(t.bankServices, own).reason, 'ok');
    assert.equal(resolveBankServiceForKid(t.bankServices, shared).reason, 'not-pinned');
    assert.equal(entry.bankServiceUrl, undefined, 'the repointed entry uses bankServices[] only');
  });
});
