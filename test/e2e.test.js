/**
 * e2e.test.js — end-to-end verifier round-trip using a fabricated
 * witness + XRPL response. No network: every fetch is stubbed.
 * Tenant registry is reset + populated synthetically per test via
 * tenantRegistry._setForTests().
 *
 * Covers (v0.1.2):
 *   - Pinned-tenant happy path (PASS)
 *   - Unsafe-override happy path (PASS)
 *   - F1 fix: JWKS kid pattern mismatch → FAIL
 *   - F2 fix: XRPL tx Account mismatch → FAIL
 *   - F4 fix: JWKS with duplicate kid → FAIL
 *   - F4 fix: JWKS with alg !== ES256 → FAIL
 *   - Witness SHA-256 tamper → FAIL
 *   - Missing Memo 5 → FAIL
 *   - Unknown tenant + no override → FAIL
 *   - Signature mismatch (wrong key) → FAIL
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { buildCanonicalInput } from '../src/canonical.js';
import { computeMerkleRoot, leafDigest } from '../src/merkle.js';
import { verify } from '../src/index.js';
import { _setForTests as setRegistryForTests, _resetForTests as resetRegistry } from '../src/tenantRegistry.js';

const TENANT = 'tvvin-prod';
const DATE = '2026-05-24';
const ENDPOINT = '/v1/balance';
const KID = 'projects/bipcircle/locations/europe-west2/keyRings/bank-service-signers/cryptoKeys/tvvin-prod-signer/cryptoKeyVersions/1';
const KID_PATTERN = '^projects/bipcircle/locations/europe-west2/keyRings/bank-service-signers/cryptoKeys/tvvin-prod-signer/cryptoKeyVersions/\\d+$';
const TXHASH = 'F'.repeat(64);
const BANK_URL = 'https://bank-service-tvvin.example';
const WITNESS_URL = `https://storage.googleapis.com/witnesses/${TENANT}/${DATE}.json`;
const ISSUER = 'rExampleIssuerAddress0000000000000000000';

function makeFixtureWorld({
  jwksKeys = null,           // override JWKS shape
  txAccount = ISSUER,        // override XRPL tx Account
  signWith = null,           // sign with a different keypair (forge test)
} = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signKey = signWith || privateKey;

  // 3 balance-read seals
  const seals = [];
  const leaves = [];
  for (let i = 1; i <= 3; i += 1) {
    const eventId = `00000000-0000-4000-8000-${i.toString().padStart(12, '0')}`;
    const signedAt = `${DATE}T10:00:0${i}.000Z`;
    const payload = {
      type: 'balance',
      provider: 'mock',
      currency: 'GBP',
      availableBalance: `${1000 + i}.00`,
      asOf: signedAt,
    };
    const canonical = buildCanonicalInput({ payload, tenantId: TENANT, eventId, signedAt, endpoint: ENDPOINT });
    const canonicalBytes = Buffer.from(canonical, 'utf8');
    const sig = crypto.sign('sha256', canonicalBytes, { key: signKey, dsaEncoding: 'der' });
    seals.push({
      eventId, signedAt,
      canonicalInput: canonicalBytes.toString('base64'),
      signature: sig.toString('base64'),
      publicKeyId: KID,
    });
    leaves.push(leafDigest(canonicalBytes));
  }
  const sealMerkleRoot = computeMerkleRoot(leaves);
  const witness = {
    protocolVersion: 'v1',
    asOfDate: DATE,
    tenantId: TENANT,
    bankServicePublicKeyId: KID,
    sealMerkleRoot,
    sealCount: seals.length,
    seals,
  };
  const witnessJson = JSON.stringify(witness);
  const witnessSha256 = crypto.createHash('sha256').update(witnessJson, 'utf8').digest('hex');

  // JWKS — default one valid key
  const jwk = publicKey.export({ format: 'jwk' });
  const jwks = jwksKeys || {
    keys: [{ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, use: 'sig', alg: 'ES256', kid: KID }],
  };

  // XRPL tx with Memo 5
  const memo5 = {
    protocolVersion: 'v1',
    sealMerkleRoot,
    witnessSha256,
    bankServicePublicKeyId: KID,
    sealCount: seals.length,
    witnessUrl: WITNESS_URL,
  };
  const hex = (s) => Buffer.from(s, 'utf8').toString('hex').toUpperCase();
  const xrplTx = {
    result: {
      Account: txAccount,
      ledger_index: 12345,
      Memos: [
        { Memo: { MemoType: hex('reserve-verifier-v1'), MemoData: hex(JSON.stringify(memo5)) } },
      ],
    },
  };

  const fetchImpl = async (url) => {
    if (typeof url === 'string' && url.includes('.well-known/bank-service-keys')) {
      return { ok: true, json: async () => jwks };
    }
    if (url === WITNESS_URL) {
      const b = Buffer.from(witnessJson, 'utf8');
      return { ok: true, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) };
    }
    return { ok: true, json: async () => xrplTx };
  };

  return { fetchImpl, witnessJson, witnessSha256, sealMerkleRoot, jwks, privateKey, publicKey };
}

beforeEach(() => {
  resetRegistry();
  setRegistryForTests({
    tenants: [{
      tenantId: TENANT,
      bankServiceUrl: BANK_URL,
      xrplIssuerAddress: ISSUER,
      kidPattern: KID_PATTERN,
      token: null,
    }],
  });
});

describe('verify — pinned-tenant happy path', () => {
  test('PASS when everything aligns with the pinned registry', async () => {
    const world = makeFixtureWorld();
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl });
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures, null, 2)}`);
    assert.equal(r.mode, 'registered-tenant');
    assert.equal(r.stages.signatures.sealsVerified, 3);
    assert.equal(r.stages.merkle.ok, true);
  });
});

describe('verify — unsafe-override mode', () => {
  test('PASS with explicit URL + issuer + no registry entry needed', async () => {
    resetRegistry();
    setRegistryForTests({ tenants: [] });
    const world = makeFixtureWorld();
    const r = await verify({
      txHash: TXHASH,
      bankServiceUrl: BANK_URL,
      xrplIssuerAddress: ISSUER,
      fetchImpl: world.fetchImpl,
    });
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures, null, 2)}`);
    assert.equal(r.mode, 'unsafe-override');
  });
});

describe('verify — F2 (XRPL account binding)', () => {
  test('FAIL when tx.Account does not match pinned xrplIssuerAddress', async () => {
    const world = makeFixtureWorld({ txAccount: 'rATTACKER0000000000000000000000000000000' });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /XRPL_ACCOUNT_MISMATCH/.test(f.reason)),
      `expected XRPL_ACCOUNT_MISMATCH, got: ${JSON.stringify(r.failures)}`);
  });
});

describe('verify — F1 (kid pattern binding)', () => {
  test('FAIL when JWKS advertises a kid that does not match tenant pinned pattern', async () => {
    // Override the registry to have a stricter pattern than the kid in the fixture
    setRegistryForTests({
      tenants: [{
        tenantId: TENANT,
        bankServiceUrl: BANK_URL,
        xrplIssuerAddress: ISSUER,
        kidPattern: '^projects/wrong-project/.+',
        token: null,
      }],
    });
    const world = makeFixtureWorld();
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(
      r.failures.some((f) => /MEMO_KID_MISMATCH|JWKS_KID_PATTERN_MISMATCH/.test(f.reason)),
      `expected kid-pattern failure, got: ${JSON.stringify(r.failures)}`,
    );
  });
});

describe('verify — F4 (JWKS hardening)', () => {
  test('FAIL on duplicate kid in JWKS', async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const world = makeFixtureWorld({
      jwksKeys: { keys: [
        { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, use: 'sig', alg: 'ES256', kid: KID },
        { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, use: 'sig', alg: 'ES256', kid: KID }, // dup
      ] },
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /duplicate kid/.test(f.reason)),
      `expected duplicate-kid failure, got: ${JSON.stringify(r.failures)}`);
  });

  test('FAIL on JWKS with alg !== ES256', async () => {
    const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const world = makeFixtureWorld({
      jwksKeys: { keys: [
        { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, use: 'sig', alg: 'ES384', kid: KID },
      ] },
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(
      r.failures.some((f) => /ES256|alg=/.test(f.reason)),
      `expected alg-mismatch failure, got: ${JSON.stringify(r.failures)}`,
    );
  });
});

describe('verify — registry handling', () => {
  test('FAIL on unknown tenant with no override', async () => {
    resetRegistry();
    setRegistryForTests({ tenants: [] });
    const world = makeFixtureWorld();
    const r = await verify({ txHash: TXHASH, tenantId: 'unknown-tenant', fetchImpl: world.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /UNKNOWN_TENANT/.test(f.reason)));
  });

  test('FAIL when neither tenant nor unsafe-override supplied', async () => {
    const world = makeFixtureWorld();
    const r = await verify({ txHash: TXHASH, fetchImpl: world.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /tenant.*OR.*unsafe/i.test(f.reason)));
  });
});

describe('verify — witness tamper', () => {
  test('FAIL when witness bytes do not match witnessSha256', async () => {
    const world = makeFixtureWorld();
    const tampered = world.witnessJson.replace(`"tenantId":"${TENANT}"`, '"tenantId":"attacker"');
    const fetchImpl = async (url, opts) => {
      if (typeof url === 'string' && url.includes('.well-known')) {
        return { ok: true, json: async () => world.jwks };
      }
      if (url === WITNESS_URL) {
        const b = Buffer.from(tampered, 'utf8');
        return { ok: true, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) };
      }
      return world.fetchImpl(url, opts);
    };
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /WITNESS_TAMPERED/.test(f.reason)));
  });
});

describe('verify — XRPL memo missing', () => {
  test('FAIL when tx has no Memo 5', async () => {
    const fetchImpl = async (url, opts) => {
      if (opts && opts.method === 'POST') {
        return { ok: true, json: async () => ({ result: { Memos: [], Account: ISSUER, ledger_index: 1 } }) };
      }
      throw new Error('unexpected');
    };
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /no 'reserve-verifier-v1' memo/.test(f.reason)));
  });
});

describe('verify — signature forgery (wrong-key seals)', () => {
  test('FAIL when seals signed with a different key than the published JWKS', async () => {
    // Generate a SEPARATE keypair to sign the seals; the JWKS still
    // advertises the original public key. ECDSA verify must reject.
    const { privateKey: attackerKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const world = makeFixtureWorld({ signWith: attackerKey });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(
      r.failures.some((f) => /seal signatures failed|ECDSA_VERIFY_FAILED/.test(f.reason)),
      `expected ECDSA verify failure, got: ${JSON.stringify(r.failures)}`,
    );
  });
});
