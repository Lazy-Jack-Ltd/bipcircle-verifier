/**
 * v0.7.1 — a tenant pinned to more than one bank-service deployment.
 *
 * Real shape: on 2026-09-27 tvvin-sandbox moved from the shared
 * bank-service-tvvin (key tvvin-signer) to its own bank-service-tvvin-sandbox
 * (key tvvin-sandbox-signer). Each deployment's JWKS lists ONLY its own key.
 * Before 0.7.1 the registry pinned the old deployment alone, so every
 * attestation signed after the move failed MEMO_KID_MISMATCH; replacing the
 * pin instead would have failed every attestation signed before it.
 *
 * The fixture reproduces that: two deployments, two keypairs, each JWKS
 * serving only its own key, and the transaction checked against the one
 * deployment its signing key belongs to.
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { buildCanonicalInput } from '../src/canonical.js';
import { computeMerkleRoot, leafDigest } from '../src/merkle.js';
import { verify } from '../src/index.js';
import {
  _setForTests as setRegistryForTests,
  _resetForTests as resetRegistry,
  lookupTenant,
  selectBankService,
} from '../src/tenantRegistry.js';

const TENANT = 'tvvin-sandbox';
const DATE = '2026-09-30';
const ENDPOINT = '/v1/balance';
const TXHASH = 'A'.repeat(64);
const PUBLISHER = 'rL78qvWguiRiTjkwX4m8WfXaA84Te1ju2u';
const TOKEN_ISSUER = 'rD1ggC6jCbHD8cK9YFs3rCmQNE8abABt34';
const WITNESS_URL = `https://storage.googleapis.com/witnesses/${TENANT}/${DATE}.json`;
const KEY_ROOT = 'projects/bipcircle/locations/europe-west2/keyRings/bank-service-signers/cryptoKeys';

const OLD = {
  url: 'https://bank-service-tvvin-yrikeqyelq-nw.a.run.app',
  kid: `${KEY_ROOT}/tvvin-signer/cryptoKeyVersions/1`,
  pattern: `^${KEY_ROOT}/tvvin-signer/cryptoKeyVersions/\\d+$`,
};
const NEW = {
  url: 'https://bank-service-tvvin-sandbox-yrikeqyelq-nw.a.run.app',
  kid: `${KEY_ROOT}/tvvin-sandbox-signer/cryptoKeyVersions/1`,
  pattern: `^${KEY_ROOT}/tvvin-sandbox-signer/cryptoKeyVersions/\\d+$`,
};

const TOKEN = {
  label: 'TVV-XRPL-Testnet', chain: 'xrpl', issuer: TOKEN_ISSUER,
  currency: 'TVV', decimals: 2, reserveCurrency: 'GBP',
};

function pin(bankServices) {
  setRegistryForTests({
    tenants: [{
      tenantId: TENANT,
      bipcircleTenantId: TENANT,
      xrplPublishingAccount: PUBLISHER,
      bankServices,
      tokens: [TOKEN],
    }],
  });
}

const BOTH = [
  { label: 'new', bankServiceUrl: NEW.url, kidPattern: NEW.pattern },
  { label: 'old', bankServiceUrl: OLD.url, kidPattern: OLD.pattern },
];

/**
 * @param signedBy   the deployment whose key signs the seals (OLD or NEW)
 * @param memoKid    the key id Memo 5 names; null omits the field
 * @param sealKids   optional per-seal key ids (defaults to signedBy.kid)
 */
function world({ signedBy, memoKid = signedBy.kid, sealKids = null }) {
  const keys = new Map([
    [OLD.url, crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })],
    [NEW.url, crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })],
  ]);
  const signer = keys.get(signedBy.url).privateKey;

  const seals = [];
  const leaves = [];
  for (let i = 1; i <= 2; i += 1) {
    const eventId = `00000000-0000-4000-8000-${i.toString().padStart(12, '0')}`;
    const signedAt = `${DATE}T10:00:0${i}.000Z`;
    const payload = { type: 'balance', provider: 'starling', currency: 'GBP', availableBalance: '3000.00', asOf: signedAt };
    const canonical = Buffer.from(
      buildCanonicalInput({ payload, tenantId: TENANT, eventId, signedAt, endpoint: ENDPOINT }), 'utf8',
    );
    seals.push({
      eventId,
      signedAt,
      canonicalInput: canonical.toString('base64'),
      signature: crypto.sign('sha256', canonical, { key: signer, dsaEncoding: 'der' }).toString('base64'),
      publicKeyId: sealKids ? sealKids[i - 1] : signedBy.kid,
    });
    leaves.push(leafDigest(canonical));
  }
  const sealMerkleRoot = computeMerkleRoot(leaves);
  const witnessJson = JSON.stringify({
    protocolVersion: 'v1', asOfDate: DATE, tenantId: TENANT,
    bankServicePublicKeyId: signedBy.kid, sealMerkleRoot, sealCount: seals.length, seals,
  });
  const witnessSha256 = crypto.createHash('sha256').update(witnessJson, 'utf8').digest('hex');

  const memo5 = { protocolVersion: 'v1', sealMerkleRoot, witnessSha256, sealCount: seals.length, witnessUrl: WITNESS_URL };
  if (memoKid !== null) memo5.bankServicePublicKeyId = memoKid;
  const record = `v1|${DATE}|xrpl-testnet|gbp.${TOKEN_ISSUER}|GBP|balanced|1000.00|1000.00|null|null|${DATE}_${TENANT}_xrpl-testnet_gbp.${TOKEN_ISSUER}`;
  const hex = (s) => Buffer.from(s, 'utf8').toString('hex').toUpperCase();
  const xrplTx = {
    result: {
      Account: PUBLISHER,
      ledger_index: 1,
      Memos: [
        { Memo: { MemoType: hex('treasury-attestation-v1'), MemoData: hex(record) } },
        { Memo: { MemoType: hex('reserve-verifier-v1'), MemoData: hex(JSON.stringify(memo5)) } },
      ],
    },
  };

  const jwksFetched = [];
  const fetchImpl = async (url, opts) => {
    if (typeof url === 'string' && url.endsWith('/.well-known/bank-service-keys')) {
      const base = url.replace('/.well-known/bank-service-keys', '');
      jwksFetched.push(base);
      const pair = keys.get(base);
      const kid = base === OLD.url ? OLD.kid : NEW.kid;
      const jwk = pair.publicKey.export({ format: 'jwk' });
      // Each deployment advertises ONLY its own key, as the real ones do.
      return { ok: true, json: async () => ({ keys: [{ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, use: 'sig', alg: 'ES256', kid }] }) };
    }
    if (url === WITNESS_URL) {
      const b = Buffer.from(witnessJson, 'utf8');
      return { ok: true, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) };
    }
    let body = {};
    try { body = JSON.parse(opts?.body || '{}'); } catch { /* not JSON */ }
    if (body.method === 'gateway_balances') {
      return { ok: true, json: async () => ({ result: { obligations: { TVV: '1000' } } }) };
    }
    return { ok: true, json: async () => xrplTx };
  };
  return { fetchImpl, jwksFetched };
}

const run = (w) => verify({ txHash: TXHASH, tenantId: TENANT, network: 'testnet', fetchImpl: w.fetchImpl });
const failed = (r, code) => r.failures.some((f) => f.reason.startsWith(code));

beforeEach(() => { resetRegistry(); pin(BOTH); });

describe('a tenant pinned to two bank-service deployments', () => {
  test('an attestation signed by the NEW deployment verifies against the new JWKS only', async () => {
    const w = world({ signedBy: NEW });
    const r = await run(w);
    assert.equal(r.verdict, 'PASS', JSON.stringify({ failures: r.failures, inconclusive: r.inconclusive }, null, 2));
    assert.deepEqual(w.jwksFetched, [NEW.url]);
    assert.equal(r.stages.jwks.bankServiceUrl, NEW.url);
    assert.equal(r.stages.registry.bankServiceCount, 2);
  });

  test('an attestation signed before the move still verifies against the OLD deployment', async () => {
    const w = world({ signedBy: OLD });
    const r = await run(w);
    assert.equal(r.verdict, 'PASS', JSON.stringify(r.failures));
    assert.deepEqual(w.jwksFetched, [OLD.url]);
  });

  test('a key id no pinned deployment owns fails MEMO_KID_MISMATCH and fetches no JWKS', async () => {
    const w = world({ signedBy: NEW, memoKid: `${KEY_ROOT}/attacker-signer/cryptoKeyVersions/1` });
    const r = await run(w);
    assert.equal(r.verdict, 'FAIL');
    assert.ok(failed(r, 'MEMO_KID_MISMATCH'), JSON.stringify(r.failures));
    assert.deepEqual(w.jwksFetched, []);
  });

  test('Memo 5 naming the old key while the seals were signed by the new key fails', async () => {
    const w = world({ signedBy: NEW, memoKid: OLD.kid });
    const r = await run(w);
    assert.equal(r.verdict, 'FAIL');
    assert.deepEqual(w.jwksFetched, [OLD.url], 'checked against the deployment the memo names, and nowhere else');
  });

  test('no key in Memo 5: the deployment comes from the seals, which must all agree', async () => {
    const ok = world({ signedBy: NEW, memoKid: null });
    const r = await run(ok);
    assert.equal(r.verdict, 'PASS', JSON.stringify(r.failures));
    assert.deepEqual(ok.jwksFetched, [NEW.url]);

    resetRegistry(); pin(BOTH);
    const mixed = world({ signedBy: NEW, memoKid: null, sealKids: [NEW.kid, OLD.kid] });
    const r2 = await run(mixed);
    assert.equal(r2.verdict, 'FAIL');
    assert.ok(failed(r2, 'SEAL_KID_UNPINNED'), JSON.stringify(r2.failures));
    assert.deepEqual(mixed.jwksFetched, []);
  });

  test('overlapping patterns are a registry defect, never a guess', async () => {
    pin([
      { label: 'a', bankServiceUrl: NEW.url, kidPattern: `^${KEY_ROOT}/.+$` },
      { label: 'b', bankServiceUrl: OLD.url, kidPattern: OLD.pattern },
    ]);
    const w = world({ signedBy: OLD });
    const r = await run(w);
    assert.equal(r.verdict, 'FAIL');
    assert.ok(failed(r, 'REGISTRY_KID_AMBIGUOUS'), JSON.stringify(r.failures));
    assert.deepEqual(w.jwksFetched, []);
  });
});

describe('registry loader: bankServices', () => {
  const tenant = (extra) => ({ tenantId: 't', xrplPublishingAccount: PUBLISHER, tokens: [TOKEN], ...extra });

  test('the single legacy form still loads as a one-entry list', () => {
    setRegistryForTests({ tenants: [tenant({ bankServiceUrl: NEW.url, kidPattern: NEW.pattern })] });
    const t = lookupTenant('t');
    assert.equal(t.bankServices.length, 1);
    assert.equal(t.bankServices[0].bankServiceUrl, NEW.url);
    assert.ok(t.bankServices[0].kidRegex.test(NEW.kid));
  });

  test('both forms at once, a missing pattern among several, a repeated URL, or http are refused', () => {
    const bad = [
      tenant({ bankServices: BOTH, bankServiceUrl: NEW.url }),
      tenant({ bankServices: [{ bankServiceUrl: NEW.url, kidPattern: NEW.pattern }, { bankServiceUrl: OLD.url }] }),
      tenant({ bankServices: [{ bankServiceUrl: NEW.url, kidPattern: NEW.pattern }, { bankServiceUrl: NEW.url, kidPattern: OLD.pattern }] }),
      tenant({ bankServices: [{ bankServiceUrl: 'http://bank.example', kidPattern: NEW.pattern }] }),
      tenant({ bankServices: [] }),
    ];
    for (const entry of bad) {
      assert.throws(() => setRegistryForTests({ tenants: [entry] }), /tenantRegistry/, JSON.stringify(entry));
    }
  });

  test('selectBankService picks exactly one match', () => {
    setRegistryForTests({ tenants: [tenant({ bankServices: BOTH })] });
    const { bankServices } = lookupTenant('t');
    assert.equal(selectBankService(bankServices, NEW.kid).service.bankServiceUrl, NEW.url);
    assert.equal(selectBankService(bankServices, OLD.kid).service.bankServiceUrl, OLD.url);
    assert.equal(selectBankService(bankServices, 'nope').service, null);
  });
});

describe('shipped src/tenants.json: tvvin-sandbox', () => {
  test('pins both deployments, new key first, and they do not overlap', () => {
    resetRegistry();
    const t = lookupTenant('tvvin-sandbox');
    const urls = t.bankServices.map((s) => s.bankServiceUrl);
    assert.deepEqual(urls, [NEW.url, OLD.url]);
    assert.equal(selectBankService(t.bankServices, NEW.kid).service.bankServiceUrl, NEW.url);
    assert.equal(selectBankService(t.bankServices, OLD.kid).service.bankServiceUrl, OLD.url);
    // The key BIPCircle staging signs with since 2026-09-27 (platform mirror:
    // bipcircle api/src/products/bipcircle/config/bankServiceTrustRoots.json).
    assert.equal(
      selectBankService(t.bankServices, `${KEY_ROOT}/tvvin-sandbox-signer/cryptoKeyVersions/7`).service.bankServiceUrl,
      NEW.url,
    );
    resetRegistry();
  });
});
