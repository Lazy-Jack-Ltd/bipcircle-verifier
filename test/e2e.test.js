/**
 * e2e.test.js — end-to-end verifier round-trip using a fabricated
 * witness + XRPL response. No network: every fetch is stubbed.
 *
 * Generates a real EC P-256 keypair, signs canonical inputs the way
 * bank-service would, wires the JWKS + witness + XRPL tx around the
 * signatures, then runs verify() and asserts PASS. Then tampers each
 * surface in turn and asserts FAIL.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { buildCanonicalInput } from '../src/canonical.js';
import { computeMerkleRoot, leafDigest } from '../src/merkle.js';
import { verify } from '../src/index.js';

const TENANT = 'tvvin-prod';
const DATE = '2026-05-24';
const ENDPOINT = '/v1/balance';
const KID = 'projects/p/locations/europe-west2/keyRings/bank-service-signers/cryptoKeys/tvvin-prod-signer/cryptoKeyVersions/1';
const TXHASH = 'F'.repeat(64);
const BANK_URL = 'https://bank-service-tvvin.example';
const WITNESS_URL = `https://storage.googleapis.com/witnesses/${TENANT}/${DATE}.json`;

function makeFixtureWorld() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

  // Build 3 balance-read seals
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
    const sig = crypto.sign('sha256', canonicalBytes, { key: privateKey, dsaEncoding: 'der' });
    seals.push({
      eventId,
      signedAt,
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

  // JWKS
  const jwk = publicKey.export({ format: 'jwk' });
  const jwks = {
    keys: [{
      kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y,
      use: 'sig', alg: 'ES256', kid: KID,
    }],
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
      Account: 'rEXAMPLE...',
      ledger_index: 12345,
      Memos: [
        { Memo: { MemoType: hex('reserve-verifier-v1'), MemoData: hex(JSON.stringify(memo5)) } },
      ],
    },
  };

  // Stub fetch
  const fetchImpl = async (url, opts) => {
    if (typeof url === 'string' && url.includes('.well-known/bank-service-keys')) {
      return { ok: true, json: async () => jwks };
    }
    if (url === WITNESS_URL) {
      const bytes = Buffer.from(witnessJson, 'utf8');
      return { ok: true, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
    }
    // XRPL RPC POST
    if (opts && opts.method === 'POST') {
      return { ok: true, json: async () => xrplTx };
    }
    throw new Error(`stub fetch: unexpected URL ${url}`);
  };

  return { fetchImpl, witnessJson, witnessSha256, sealMerkleRoot, jwks, privateKey, publicKey };
}

describe('verify — end-to-end happy path', () => {
  test('PASS for a well-formed witness round-trip', async () => {
    const world = makeFixtureWorld();
    const r = await verify({
      txHash: TXHASH,
      network: 'mainnet',
      bankServiceUrl: BANK_URL,
      fetchImpl: world.fetchImpl,
    });
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures, null, 2)}`);
    assert.equal(r.stages.signatures.sealsVerified, 3);
    assert.equal(r.stages.merkle.ok, true);
    assert.equal(r.stages.witness.sealCount, 3);
  });
});

describe('verify — tamper paths', () => {
  test('FAIL when witness bytes don\'t match witnessSha256', async () => {
    const world = makeFixtureWorld();
    // Override fetch to return DIFFERENT witness bytes (mutate the
    // tenantId — guaranteed to appear in the witness JSON and to flip
    // the SHA-256).
    const tampered = world.witnessJson.replace(`"tenantId":"${TENANT}"`, '"tenantId":"attacker"');
    const fetchImpl = async (url, opts) => {
      if (typeof url === 'string' && url.includes('.well-known')) {
        return { ok: true, json: async () => world.jwks };
      }
      if (url === WITNESS_URL) {
        const b = Buffer.from(tampered, 'utf8');
        return { ok: true, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) };
      }
      return { ok: true, json: async () => (await world.fetchImpl(url, opts).then((r) => r.json())) };
    };
    const r = await verify({ txHash: TXHASH, bankServiceUrl: BANK_URL, fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /WITNESS_TAMPERED/.test(f.reason)));
  });

  test('FAIL when XRPL tx has no Memo 5', async () => {
    const fetchImpl = async (url, opts) => {
      if (opts && opts.method === 'POST') {
        return { ok: true, json: async () => ({ result: { Memos: [], Account: 'r', ledger_index: 1 } }) };
      }
      throw new Error('unexpected');
    };
    const r = await verify({ txHash: TXHASH, bankServiceUrl: BANK_URL, fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /no 'reserve-verifier-v1' memo/.test(f.reason)));
  });

  test('FAIL when bankServiceUrl is missing', async () => {
    const world = makeFixtureWorld();
    const r = await verify({ txHash: TXHASH, bankServiceUrl: '', fetchImpl: world.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /bankServiceUrl is required/.test(f.reason)));
  });
});
