/**
 * registryIdentity.test.js — v0.7.0.
 *
 * The registry conflated two on-chain identities: it pinned the XRPL TOKEN
 * ISSUER as the account the attestation transaction must be signed by, while
 * the producer signs from a separate per-tenant anchor wallet. Every genuine
 * attestation therefore failed the F2 account check.
 *
 * These tests pin the separation itself, not just the corrected values:
 *
 *   - the shipped registry keeps publishing account, XRPL token issuer and
 *     EVM contract as three distinct values
 *   - a transaction signed by the TOKEN ISSUER is still rejected (the exact
 *     shape of the original bug)
 *   - the witness must name the pinned platform tenant
 *   - a hole in the registry reports as a registry defect, never as evidence
 *     against the transaction
 *   - a check this tool could not PERFORM is INCONCLUSIVE, never FAIL
 *   - a published drift verdict FAILs and says why on the headline
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { buildCanonicalInput } from '../src/canonical.js';
import { computeMerkleRoot, leafDigest } from '../src/merkle.js';
import { verify } from '../src/index.js';
import { renderHuman } from '../src/report.js';
import {
  loadTenantRegistry,
  lookupTenant,
  _setForTests as setRegistryForTests,
  _resetForTests as resetRegistry,
} from '../src/tenantRegistry.js';

// ── Fixture constants ────────────────────────────────────────────────────
const PIN = 'acme-sandbox';
const PLATFORM_TENANT = 'acme-sandbox';
const DATE = '2026-09-19';
const ENDPOINT = '/v1/balance';
const KID = 'projects/p/locations/l/keyRings/bank-service-signers/cryptoKeys/acme-signer/cryptoKeyVersions/1';
const KID_PATTERN = '^projects/p/locations/l/keyRings/bank-service-signers/cryptoKeys/acme-signer/cryptoKeyVersions/\\d+$';
const TXHASH = 'A'.repeat(64);
const BANK_URL = 'https://bank-service-acme.example';
const WITNESS_URL = `https://storage.googleapis.com/witnesses/${PLATFORM_TENANT}/${DATE}.json`;

// THE THREE IDENTITIES — deliberately different strings.
const PUBLISHING_ACCOUNT = 'rPUBLISHacct0000000000000000000000';
const XRPL_TOKEN_ISSUER = 'rISSUERtoken00000000000000000000000';
const ETH_CONTRACT = '0x1111111111111111111111111111111111111111';

/** A combined-row record binds to the GBP cell whatever tokens it holds. */
function combinedRecord({ verdict = 'balanced', currency = 'GBP', date = DATE } = {}) {
  return `v2|${date}|combined|combined:${currency}|${currency}|${verdict}|1000.00|1000.00|1000.00|0|${date}_${PLATFORM_TENANT}_combined_${currency}`;
}

/**
 * Build a coherent evidence world: 1 GBP balance seal of £1,000.00, a witness
 * committing to it, a JWKS holding the signing key, and an XRPL tx anchoring
 * the witness. Callers override the pieces each test is about.
 */
function makeWorld({
  txAccount = PUBLISHING_ACCOUNT,
  witnessTenantId = PLATFORM_TENANT,
  canonicalRecord = combinedRecord(),
  bankBalance = '1000.00',
  xrplObligations = '500',
  ethSupplyHex = null,
} = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

  const eventId = '00000000-0000-4000-8000-000000000001';
  const signedAt = `${DATE}T10:00:00.000Z`;
  const payload = {
    type: 'balance',
    provider: 'mock',
    currency: 'GBP',
    availableBalance: bankBalance,
    asOf: signedAt,
  };
  const canonical = buildCanonicalInput({ payload, tenantId: witnessTenantId, eventId, signedAt, endpoint: ENDPOINT });
  const canonicalBytes = Buffer.from(canonical, 'utf8');
  const sig = crypto.sign('sha256', canonicalBytes, { key: privateKey, dsaEncoding: 'der' });
  const seals = [{
    eventId,
    signedAt,
    canonicalInput: canonicalBytes.toString('base64'),
    signature: sig.toString('base64'),
    publicKeyId: KID,
  }];
  const sealMerkleRoot = computeMerkleRoot([leafDigest(canonicalBytes)]);

  const witness = {
    protocolVersion: 'v1',
    asOfDate: DATE,
    tenantId: witnessTenantId,
    bankServicePublicKeyId: KID,
    sealMerkleRoot,
    sealCount: seals.length,
    seals,
  };
  const witnessJson = JSON.stringify(witness);
  const witnessSha256 = crypto.createHash('sha256').update(witnessJson, 'utf8').digest('hex');

  const jwk = publicKey.export({ format: 'jwk' });
  const jwks = { keys: [{ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, use: 'sig', alg: 'ES256', kid: KID }] };

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
      ledger_index: 999,
      Memos: [
        ...(canonicalRecord ? [{ Memo: { MemoType: hex('treasury-attestation-v1'), MemoData: hex(canonicalRecord) } }] : []),
        { Memo: { MemoType: hex('reserve-verifier-v1'), MemoData: hex(JSON.stringify(memo5)) } },
      ],
    },
  };

  const fetchImpl = async (url, opts) => {
    if (typeof url === 'string' && url.includes('.well-known/bank-service-keys')) {
      return { ok: true, json: async () => jwks };
    }
    if (url === WITNESS_URL) {
      const b = Buffer.from(witnessJson, 'utf8');
      return { ok: true, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) };
    }
    let body = {};
    try { body = JSON.parse(opts?.body || '{}'); } catch { /* not JSON */ }
    if (body.method === 'gateway_balances') {
      return { ok: true, json: async () => ({ result: { obligations: { TVV: xrplObligations } } }) };
    }
    if (body.method === 'eth_call') {
      return { ok: true, json: async () => ({ result: ethSupplyHex || '0x0' }) };
    }
    return { ok: true, json: async () => xrplTx };
  };

  return { fetchImpl };
}

const XRPL_TOKEN = {
  label: 'TVV-XRPL', chain: 'xrpl', issuer: XRPL_TOKEN_ISSUER,
  currency: 'TVV', decimals: 2, reserveCurrency: 'GBP',
};
const ETH_TOKEN = {
  label: 'ACME-ETH', chain: 'ethereum', contract: ETH_CONTRACT,
  decimals: 2, currency: 'GBP', reserveCurrency: 'GBP',
};

function pinRegistry(overrides = {}) {
  setRegistryForTests({
    tenants: [{
      tenantId: PIN,
      bipcircleTenantId: PLATFORM_TENANT,
      bankServiceUrl: BANK_URL,
      xrplPublishingAccount: PUBLISHING_ACCOUNT,
      kidPattern: KID_PATTERN,
      tokens: [XRPL_TOKEN],
      ...overrides,
    }],
  });
}

beforeEach(() => { resetRegistry(); pinRegistry(); });

// ── The shipped registry ─────────────────────────────────────────────────

describe('shipped src/tenants.json', () => {
  test('tvvin-sandbox is present and evaluable', () => {
    resetRegistry();
    const t = lookupTenant('tvvin-sandbox');
    assert.ok(t, 'tvvin-sandbox must be a pinned tenant — it is the deployment that publishes');
    assert.equal(t.bipcircleTenantId, 'tvvin-sandbox');
    assert.ok(t.xrplPublishingAccount, 'must pin a publishing account or there is no F2 trust root');
    assert.ok(t.tokens.length > 0, 'must pin tokens or the supply check can never run');
    resetRegistry();
  });

  test('the publishing account is NOT any token issuer and NOT any contract', () => {
    resetRegistry();
    const t = lookupTenant('tvvin-sandbox');
    const issuers = t.tokens.filter((k) => k.chain === 'xrpl').map((k) => k.issuer);
    const contracts = t.tokens.filter((k) => k.chain === 'ethereum').map((k) => k.contract);
    assert.ok(issuers.length > 0 && contracts.length > 0, 'fixture assumption: entry spans both chains');
    assert.ok(
      !issuers.includes(t.xrplPublishingAccount),
      'REGRESSION: the publishing account equals an XRPL token issuer — the two identities have been re-merged',
    );
    assert.ok(
      !contracts.map((c) => c.toLowerCase()).includes(String(t.xrplPublishingAccount).toLowerCase()),
      'the publishing account equals an EVM contract address',
    );
    resetRegistry();
  });

  test('no XRPL token is pinned at a precision the ledger cannot fit', () => {
    // An XRPL issued currency has no on-ledger decimals field — gateway_balances
    // returns a decimal string, and fractional obligations are the normal case
    // (TVV stands at 2191947.52 today). A token pinned at 0dp therefore cannot
    // represent its own supply, and the cell becomes unverifiable. 2dp is the
    // floor for anything denominated against a fiat cell.
    resetRegistry();
    for (const t of loadTenantRegistry().tenants) {
      for (const tok of t.tokens.filter((k) => k.chain === 'xrpl')) {
        assert.ok(
          Number.isInteger(tok.decimals) && tok.decimals >= 2,
          `tenant '${t.tenantId}' token '${tok.label}' pins decimals=${tok.decimals}; an XRPL token needs `
          + 'at least 2 to represent a fractional obligation',
        );
      }
    }
    resetRegistry();
  });

  test('every pinned tenant resolves a publishing account', () => {
    resetRegistry();
    for (const t of loadTenantRegistry().tenants) {
      assert.ok(t.xrplPublishingAccount, `tenant '${t.tenantId}' has no publishing account`);
    }
    resetRegistry();
  });
});

// ── Alias handling ───────────────────────────────────────────────────────

describe('deprecated xrplIssuerAddress alias', () => {
  test('an entry using only the old name still gets an F2 trust root', () => {
    setRegistryForTests({
      tenants: [{ tenantId: 'legacy', bankServiceUrl: BANK_URL, xrplIssuerAddress: PUBLISHING_ACCOUNT, tokens: [] }],
    });
    assert.equal(lookupTenant('legacy').xrplPublishingAccount, PUBLISHING_ACCOUNT);
  });

  test('an entry setting BOTH names to different accounts is refused at load', () => {
    assert.throws(
      () => setRegistryForTests({
        tenants: [{
          tenantId: 'conflict',
          bankServiceUrl: BANK_URL,
          xrplPublishingAccount: PUBLISHING_ACCOUNT,
          xrplIssuerAddress: XRPL_TOKEN_ISSUER,
          tokens: [],
        }],
      }),
      /different values/,
      'a disagreement about the F2 trust root must never be silently resolved',
    );
  });

  test('bipcircleTenantId defaults to the pin name when absent', () => {
    setRegistryForTests({
      tenants: [{ tenantId: 'plain', bankServiceUrl: BANK_URL, xrplPublishingAccount: PUBLISHING_ACCOUNT, tokens: [] }],
    });
    assert.equal(lookupTenant('plain').bipcircleTenantId, 'plain');
  });
});

// ── F2: the original conflation ──────────────────────────────────────────

describe('F2 — the attestation must be signed by the publishing account', () => {
  test('a tx signed by the pinned publishing account is accepted', async () => {
    const w = makeWorld();
    const r = await verify({ txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl });
    assert.equal(r.stages.xrpl.ok, true);
    assert.ok(!r.failures.some((f) => /XRPL_ACCOUNT_MISMATCH/.test(f.reason)));
  });

  test('a tx signed by the XRPL TOKEN ISSUER is REJECTED (the exact original bug)', async () => {
    const w = makeWorld({ txAccount: XRPL_TOKEN_ISSUER });
    const r = await verify({ txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    const f = r.failures.find((x) => /XRPL_ACCOUNT_MISMATCH/.test(x.reason));
    assert.ok(f, 'a token issuer is not a publisher — this must not verify');
    assert.match(f.reason, /not a token issuer|token issuer/i);
  });

  test('a registry entry with NO publishing account blames the registry, not the tx', async () => {
    pinRegistry({ xrplPublishingAccount: undefined });
    const w = makeWorld();
    const r = await verify({ txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    const f = r.failures.find((x) => /REGISTRY_ENTRY_INCOMPLETE/.test(x.reason));
    assert.ok(f, 'a hole in tenants.json must be named as such');
    assert.ok(
      !r.failures.some((x) => /XRPL_ACCOUNT_MISMATCH/.test(x.reason)),
      'must NOT read as evidence against the transaction',
    );
  });
});

// ── Witness ↔ platform tenant binding ────────────────────────────────────

describe('witness tenant binding', () => {
  test('a witness naming a DIFFERENT platform tenant FAILs', async () => {
    const w = makeWorld({ witnessTenantId: 'someone-else' });
    const r = await verify({ txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(
      r.failures.some((f) => /WITNESS_TENANT_MISMATCH/.test(f.reason)),
      "another deployment's reserve evidence must not back this transaction",
    );
  });

  test('a witness naming the pinned platform tenant raises no tenant failure', async () => {
    const w = makeWorld();
    const r = await verify({ txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl });
    assert.ok(!r.failures.some((f) => /WITNESS_TENANT_MISMATCH/.test(f.reason)));
  });

  test('the binding follows bipcircleTenantId, NOT the pin name', async () => {
    // Pin name and platform tenant id deliberately differ: the witness names
    // the platform tenant, so this must pass the binding even though the
    // witness tenantId does not equal `--tenant`.
    pinRegistry({ tenantId: PIN, bipcircleTenantId: 'platform-side-id' });
    const w = makeWorld({ witnessTenantId: 'platform-side-id' });
    const r = await verify({ txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl });
    assert.ok(
      !r.failures.some((f) => /WITNESS_TENANT_MISMATCH/.test(f.reason)),
      'the pin name is a CLI label; the witness is bound to the platform tenant id',
    );
  });
});

// ── Published verdict ────────────────────────────────────────────────────

describe('a published out_of_tolerance', () => {
  test('FAILs, and the reserve comparison still runs', async () => {
    const w = makeWorld({ canonicalRecord: combinedRecord({ verdict: 'out_of_tolerance' }) });
    const r = await verify({ txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    const f = r.failures.find((x) => /PUBLISHED_VERDICT_DRIFT/.test(x.reason));
    assert.ok(f, "the issuer's own declared drift must FAIL");
    assert.match(f.reason, /out_of_tolerance/);
    assert.equal(r.stages.record.verdict, 'out_of_tolerance');
    // The drift disclosure must not short-circuit the independent check.
    assert.ok(Array.isArray(r.stages.supply.cells), 'the reserve comparison must still run');
  });

  test('the rendered report headlines it as a reserve discrepancy, not a tool fault', async () => {
    const w = makeWorld({ canonicalRecord: combinedRecord({ verdict: 'out_of_tolerance' }) });
    const r = await verify({ txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl });
    const out = renderHuman(r, { network: 'testnet', txHash: TXHASH });
    assert.match(out, /VERDICT: FAIL/);
    assert.match(out, /DETECTED RESERVE DISCREPANCY/);
    assert.match(out, /not a verifier malfunction/);
    assert.match(out, /published verdict:\s+out_of_tolerance/);
  });

  test('a genuine shortfall FAILs with the cell named', async () => {
    // £10.00 of reserve behind 500 TVV (=500.00 at 2dp) in the GBP cell.
    const w = makeWorld({ bankBalance: '10.00', xrplObligations: '500' });
    const r = await verify({ txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /RESERVE_SHORTFALL\[GBP\]/.test(f.reason)));
  });
});

// ── Could-not-perform is not could-not-back ──────────────────────────────

describe('a check this tool could not PERFORM is INCONCLUSIVE, never FAIL', () => {
  test('a missing --eth-rpc-url is INCONCLUSIVE, not a reserve failure', async () => {
    pinRegistry({ tokens: [ETH_TOKEN] });
    const w = makeWorld();
    const r = await verify({ txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl /* no ethRpcUrl */ });
    assert.equal(r.verdict, 'INCONCLUSIVE', 'forgetting a flag is not evidence the reserve is short');
    assert.equal(r.failures.length, 0, 'must raise NO failure');
    assert.ok(r.inconclusive.some((f) => /ETH_RPC_URL_NOT_SUPPLIED/.test(f.reason)));
    assert.ok(r.inconclusive.some((f) => /--eth-rpc-url/.test(f.reason)), 'must say how to fix it');
  });

  test('with --eth-rpc-url supplied the ethereum cell actually verifies', async () => {
    pinRegistry({ tokens: [ETH_TOKEN] });
    // 0x3e8 = 1000 minor units = £10.00 at 2dp, under £1,000.00 of reserve.
    const w = makeWorld({ ethSupplyHex: '0x3e8' });
    const r = await verify({
      txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl,
      ethRpcUrl: 'https://eth.example',
    });
    assert.equal(r.verdict, 'PASS', `failures=${JSON.stringify(r.failures)} inconclusive=${JSON.stringify(r.inconclusive)}`);
    assert.equal(r.stages.supply.cells[0].ok, true);
  });

  test('XRPL obligations finer than the pinned decimals are INCONCLUSIVE, not a shortfall', async () => {
    // decimals: 2 pinned, ledger reports 4 fractional digits.
    const w = makeWorld({ xrplObligations: '500.1234' });
    const r = await verify({ txHash: TXHASH, tenantId: PIN, fetchImpl: w.fetchImpl });
    assert.equal(r.verdict, 'INCONCLUSIVE', 'a registry precision gap is not a reserve shortfall');
    assert.equal(r.failures.length, 0);
    const i = r.inconclusive.find((f) => /XRPL_SUPPLY_PRECISION_UNPINNED/.test(f.reason));
    assert.ok(i, 'must name the cause');
    assert.match(i.reason, /decimals=2/);
    assert.match(i.reason, /tenants\.json/, 'must say where to fix it');
  });

  test('an unsafe override can never reach PASS', async () => {
    resetRegistry();
    setRegistryForTests({ tenants: [] });
    const w = makeWorld();
    const r = await verify({
      txHash: TXHASH,
      bankServiceUrl: BANK_URL,
      xrplIssuerAddress: PUBLISHING_ACCOUNT,
      fetchImpl: w.fetchImpl,
    });
    assert.equal(r.mode, 'unsafe-override');
    assert.notEqual(r.verdict, 'PASS');
    assert.ok(r.inconclusive.some((f) => /SUPPLY_CHECK_NOT_RUN/.test(f.reason)));
  });
});
