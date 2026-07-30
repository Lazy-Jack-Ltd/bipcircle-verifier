/**
 * perCell.test.js — regression pins for the 2026-07-29 protected-cell-company
 * audit (reserve-attestation-cell-and-multibank-audit-20260729.md, findings
 * 2, 3, 4, 5, 18, 19).
 *
 * The issuer is a protected cell company: each cell holds ONE fiat currency
 * and is legally segregated. Cell A's surplus can never cover cell B's
 * shortfall. Pre-0.5.0 the verifier summed every token's supply into one pot
 * and compared it against ONE currency's reserves — each test here pins the
 * exact false-PASS / false-FAIL that allowed, executed end-to-end through
 * verify() with stubbed fetch (no network).
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { buildCanonicalInput } from '../src/canonical.js';
import { computeMerkleRootForVersion, leafDigest } from '../src/merkle.js';
import { verify } from '../src/index.js';
import { sumBankReservesDetailed } from '../src/onchain.js';
import { _setForTests as setRegistryForTests, _resetForTests as resetRegistry } from '../src/tenantRegistry.js';

const TENANT = 'tvvin-cells';
const DATE = '2026-07-29';
const ENDPOINT = '/v1/balance';
const KID = 'projects/bipcircle/locations/europe-west2/keyRings/bank-service-signers/cryptoKeys/tvvin-cells-signer/cryptoKeyVersions/1';
const KID_PATTERN = '^projects/bipcircle/locations/europe-west2/keyRings/bank-service-signers/cryptoKeys/tvvin-cells-signer/cryptoKeyVersions/\\d+$';
const TXHASH = 'F'.repeat(64);
const BANK_URL = 'https://bank-service-cells.example';
const WITNESS_URL = `https://storage.googleapis.com/witnesses/${TENANT}/${DATE}.json`;
const ISSUER = 'rExampleIssuerAddress0000000000000000000';
const ETH_RPC = 'https://eth-rpc.example';

const EUR_CONTRACT = `0x${'aa'.repeat(20)}`;
const GBP_CONTRACT = `0x${'bb'.repeat(20)}`;
const GBP18_CONTRACT = `0x${'cc'.repeat(20)}`;

/**
 * The eleven-field Memo 1 canonical record exactly as the producer's
 * buildCanonicalRecord emits it (major-unit figures as strings; the literal
 * 'null' = "this view was never committed", which is NOT zero). Every real
 * attestation transaction since 2026-05-23 carries this memo alongside
 * Memo 5, so the fixture worlds carry one too (v0.6.0 binds the verdict to
 * the cell it names).
 */
function rec(chain, tokenKey, currency, {
  version = 'v2', verdict = 'balanced',
  onChain = 'null', ledger = 'null', bank = 'null', delta = 'null',
} = {}) {
  return [version, DATE, chain, tokenKey, currency, verdict, onChain, ledger, bank, delta,
    `${DATE}_${TENANT}_${chain}_${tokenKey}`].join('|');
}

/**
 * Build a fully-signed world: seals -> witness -> Memo 1 + Memo 5 tx -> stub
 * fetch. sealSpecs entries are merged into the balance payload (provider,
 * currency, availableBalance, optional bankAccountId, ...). canonicalRecord
 * is the Memo 1 payload (build with rec()); null omits the memo entirely.
 */
function makeWorld({ sealSpecs, ethSupplies = {}, xrplObligations = {}, protocolVersion = 'v1', canonicalRecord = null }) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const seals = [];
  const leaves = [];
  sealSpecs.forEach((spec, i) => {
    const eventId = `00000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}`;
    const signedAt = `${DATE}T10:00:0${i}.000Z`;
    const payload = { type: 'balance', endpoint: ENDPOINT, asOf: signedAt, ...spec };
    const canonical = buildCanonicalInput({ payload, tenantId: TENANT, eventId, signedAt, endpoint: ENDPOINT });
    const bytes = Buffer.from(canonical, 'utf8');
    const sig = crypto.sign('sha256', bytes, { key: privateKey, dsaEncoding: 'der' });
    seals.push({ eventId, signedAt, canonicalInput: bytes.toString('base64'), signature: sig.toString('base64'), publicKeyId: KID });
    leaves.push(leafDigest(bytes));
  });
  const sealMerkleRoot = computeMerkleRootForVersion(leaves, protocolVersion);
  const witness = { protocolVersion, asOfDate: DATE, tenantId: TENANT, bankServicePublicKeyId: KID, sealMerkleRoot, sealCount: seals.length, seals };
  const witnessJson = JSON.stringify(witness);
  const witnessSha256 = crypto.createHash('sha256').update(witnessJson, 'utf8').digest('hex');
  const jwk = publicKey.export({ format: 'jwk' });
  const jwks = { keys: [{ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, use: 'sig', alg: 'ES256', kid: KID }] };
  const memo5 = { protocolVersion, sealMerkleRoot, witnessSha256, bankServicePublicKeyId: KID, sealCount: seals.length, witnessUrl: WITNESS_URL };
  const hex = (s) => Buffer.from(s, 'utf8').toString('hex').toUpperCase();
  const memos = [
    ...(canonicalRecord ? [{ Memo: { MemoType: hex('treasury-attestation-v1'), MemoData: hex(canonicalRecord) } }] : []),
    { Memo: { MemoType: hex('reserve-verifier-v1'), MemoData: hex(JSON.stringify(memo5)) } },
  ];
  const xrplTx = { result: { Account: ISSUER, ledger_index: 12345, Memos: memos } };

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
    if (body.method === 'eth_call') {
      const to = body.params?.[0]?.to?.toLowerCase();
      const supply = ethSupplies[to] ?? 0n;
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: `0x${supply.toString(16)}` }) };
    }
    if (body.method === 'gateway_balances') {
      return { ok: true, json: async () => ({ result: { obligations: xrplObligations } }) };
    }
    return { ok: true, json: async () => xrplTx };
  };
  return { fetchImpl };
}

function setRegistry(tokens) {
  resetRegistry();
  setRegistryForTests({ tenants: [{ tenantId: TENANT, bankServiceUrl: BANK_URL, xrplIssuerAddress: ISSUER, kidPattern: KID_PATTERN, tokens }] });
}

beforeEach(() => resetRegistry());

describe('finding 2 — a cell is verified against ITS OWN reserves only (no cross-currency netting)', () => {
  const tokens = [
    { label: 'EURS-ETH', chain: 'ethereum', contract: EUR_CONTRACT, decimals: 2, currency: 'EUR', reserveCurrency: 'EUR' },
    { label: 'GBPS-ETH', chain: 'ethereum', contract: GBP_CONTRACT, decimals: 2, currency: 'GBP', reserveCurrency: 'GBP' },
  ];
  const sealSpecs = [
    { provider: 'clearbank', currency: 'EUR', availableBalance: '10000000.00' }, // EUR 10m surplus
    { provider: 'clearbank', currency: 'GBP', availableBalance: '500000.00' },   // GBP 500k — half the supply
  ];
  const ethSupplies = { [EUR_CONTRACT]: 10000n, [GBP_CONTRACT]: 100000000n };    // EUR 100, GBP 1,000,000

  test('FAIL: a GBP-cell tx must FAIL on its £500,000 shortfall — an EUR surplus in the same witness cannot cover it (pre-0.5.0 false PASS)', async () => {
    setRegistry(tokens);
    const world = makeWorld({ sealSpecs, ethSupplies, canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP') });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /RESERVE_SHORTFALL\[GBP\]/.test(f.reason)),
      `expected a GBP-cell shortfall, got: ${JSON.stringify(r.failures)}`);
    // v0.6.0 — the check is SCOPED to the cell the tx's record names.
    assert.equal(r.stages.supply.verifiedCell, 'GBP');
    assert.equal(r.stages.supply.cells.length, 1);
    const gbp = r.stages.supply.cells[0];
    assert.equal(gbp.ok, false);
    assert.equal(gbp.shortfallMinorUnits, '50000000'); // £500,000.00 short
  });

  test('v0.6.0 — an EUR-cell tx against the SAME world answers for the EUR cell: PASS (no longer byte-identical to the GBP tx)', async () => {
    setRegistry(tokens);
    const world = makeWorld({ sealSpecs, ethSupplies, canonicalRecord: rec('ethereum-sepolia', EUR_CONTRACT, 'EUR') });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC });
    // The EUR cell is genuinely healthy; the GBP shortfall belongs to the
    // GBP cell's OWN transaction (previous test). Cells are legally
    // segregated — each verdict speaks for the cell its tx names.
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures)} inconclusive: ${JSON.stringify(r.inconclusive)}`);
    assert.equal(r.stages.supply.verifiedCell, 'EUR');
    assert.equal(r.stages.supply.cells.length, 1);
    assert.equal(r.stages.supply.cells[0].ok, true);
  });

  test('PASS when the named cell is individually backed', async () => {
    setRegistry(tokens);
    const healthySeals = [
      { provider: 'clearbank', currency: 'EUR', availableBalance: '100.00' },
      { provider: 'clearbank', currency: 'GBP', availableBalance: '1000000.00' },
    ];
    for (const [tokenKey, cell] of [[GBP_CONTRACT, 'GBP'], [EUR_CONTRACT, 'EUR']]) {
      const world = makeWorld({ sealSpecs: healthySeals, ethSupplies, canonicalRecord: rec('ethereum-sepolia', tokenKey, cell) });
      const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC });
      assert.equal(r.verdict, 'PASS', `[${cell}] failures: ${JSON.stringify(r.failures)} inconclusive: ${JSON.stringify(r.inconclusive)}`);
      assert.equal(r.stages.supply.verifiedCell, cell);
      assert.ok(r.stages.supply.cells.every((c) => c.ok));
    }
  });
});

describe('finding 5 — a token with no resolvable cell currency can never yield PASS', () => {
  test('INCONCLUSIVE: ethereum token missing both reserveCurrency and currency', async () => {
    setRegistry([{ label: 'GBPS-ETH', chain: 'ethereum', contract: GBP_CONTRACT, decimals: 2 }]);
    const world = makeWorld({
      sealSpecs: [
        { provider: 'clearbank', currency: 'EUR', availableBalance: '10000000.00' },
        { provider: 'clearbank', currency: 'GBP', availableBalance: '500000.00' },
      ],
      ethSupplies: { [GBP_CONTRACT]: 100000000n },
      canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP'),
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC });
    // Pre-0.5.0: reservesCurrency fell back to '' which DISABLED the currency
    // filter — EUR 10m + GBP 500k backed £1m of GBP supply → false PASS.
    assert.notEqual(r.verdict, 'PASS');
    assert.equal(r.verdict, 'INCONCLUSIVE');
    assert.ok(r.inconclusive.some((f) => /CELL_CURRENCY_UNRESOLVED/.test(f.reason)));
  });

  test('INCONCLUSIVE: xrpl token without reserveCurrency (its `currency` is a ticker, never a cell)', async () => {
    setRegistry([{ label: 'TVV-XRPL', chain: 'xrpl', issuer: ISSUER, currency: 'TVV', decimals: 2 }]);
    const world = makeWorld({
      sealSpecs: [{ provider: 'clearbank', currency: 'GBP', availableBalance: '1000000.00' }],
      xrplObligations: { TVV: '1000' },
      canonicalRecord: rec('xrpl-testnet', `gbp.${ISSUER}`, 'GBP'),
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl });
    assert.equal(r.verdict, 'INCONCLUSIVE');
    assert.ok(r.inconclusive.some((f) => /CELL_CURRENCY_UNRESOLVED/.test(f.reason)));
  });

  test('legacy ethereum entries still resolve: `currency` alone is an accepted fiat fallback', async () => {
    setRegistry([{ label: 'GBPS-ETH', chain: 'ethereum', contract: GBP_CONTRACT, decimals: 2, currency: 'GBP' }]);
    const world = makeWorld({
      sealSpecs: [{ provider: 'clearbank', currency: 'GBP', availableBalance: '1000000.00' }],
      ethSupplies: { [GBP_CONTRACT]: 100000000n },
      canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP'),
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC });
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures)} inconclusive: ${JSON.stringify(r.inconclusive)}`);
  });
});

describe('finding 3 — several accounts at ONE provider all count (no same-provider collapse)', () => {
  test('PASS: two ClearBank GBP accounts (600k + 400k) fully back £1m supply (pre-0.5.0 false FAIL)', async () => {
    setRegistry([{ label: 'GBPS-ETH', chain: 'ethereum', contract: GBP_CONTRACT, decimals: 2, currency: 'GBP', reserveCurrency: 'GBP' }]);
    const world = makeWorld({
      sealSpecs: [
        { provider: 'clearbank', currency: 'GBP', availableBalance: '600000.00', bankAccountId: 'cb-acct-1' },
        { provider: 'clearbank', currency: 'GBP', availableBalance: '400000.00', bankAccountId: 'cb-acct-2' },
      ],
      ethSupplies: { [GBP_CONTRACT]: 100000000n },
      canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP'),
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC });
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures)} inconclusive: ${JSON.stringify(r.inconclusive)}`);
    const cell = r.stages.supply.cells[0];
    assert.equal(cell.reservesMinorUnits, '100000000'); // £600k + £400k
    assert.equal(cell.reserveAccountCount, 2);
  });

  test('intra-day re-reads of the SAME account still dedup to the latest', () => {
    const seal = (eventId, asOf, availableBalance) => {
      const payload = { type: 'balance', endpoint: ENDPOINT, provider: 'clearbank', currency: 'GBP', bankAccountId: 'cb-acct-1', availableBalance, asOf };
      return { eventId, signedAt: asOf, canonicalInput: Buffer.from(JSON.stringify(payload), 'utf8').toString('base64') };
    };
    const out = sumBankReservesDetailed([
      seal('e1', '2026-07-29T09:00:00Z', '600000.00'),
      seal('e2', '2026-07-29T17:00:00Z', '550000.00'),
    ], 2, 'GBP');
    assert.equal(out.totalMinorUnits, 55000000n); // the 17:00 read, once
    assert.equal(out.accountCount, 1);
  });

  test('REFUSED: one provider mixing account-referenced and unreferenced seals (double-count ambiguity)', () => {
    const seal = (eventId, payloadExtra) => {
      const payload = { type: 'balance', endpoint: ENDPOINT, provider: 'clearbank', currency: 'GBP', availableBalance: '100.00', asOf: '2026-07-29T09:00:00Z', ...payloadExtra };
      return { eventId, signedAt: '2026-07-29T09:00:00Z', canonicalInput: Buffer.from(JSON.stringify(payload), 'utf8').toString('base64') };
    };
    assert.throws(
      () => sumBankReservesDetailed([seal('e1', { bankAccountId: 'cb-acct-1' }), seal('e2', {})], 2, 'GBP'),
      /POR-MULTIBANK-ACCOUNT-01/,
    );
  });
});

describe('finding 4 — absence can never read as PASS', () => {
  test('INCONCLUSIVE: registered tenant with ZERO tokens (reserve check never ran)', async () => {
    setRegistry([]);
    const world = makeWorld({
      sealSpecs: [{ provider: 'clearbank', currency: 'GBP', availableBalance: '0.00' }],
      canonicalRecord: rec('combined', 'combined:gbp', 'GBP'),
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl });
    assert.equal(r.verdict, 'INCONCLUSIVE'); // pre-0.5.0: PASS, exit 0
    assert.equal(r.failures.length, 0);
    assert.ok(r.inconclusive.some((f) => /SUPPLY_CHECK_NOT_RUN/.test(f.reason)));
  });

  test('INCONCLUSIVE: --skip-onchain with zero reserves against £1m supply (pre-0.5.0 false PASS)', async () => {
    setRegistry([{ label: 'GBPS-ETH', chain: 'ethereum', contract: GBP_CONTRACT, decimals: 2, currency: 'GBP', reserveCurrency: 'GBP' }]);
    const world = makeWorld({
      sealSpecs: [{ provider: 'clearbank', currency: 'GBP', availableBalance: '0.00' }],
      ethSupplies: { [GBP_CONTRACT]: 100000000n },
      canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP'),
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, skipOnChainSupply: true });
    assert.equal(r.verdict, 'INCONCLUSIVE');
    assert.ok(r.inconclusive.some((f) => /SUPPLY_CHECK_SKIPPED/.test(f.reason)));
  });

  test('FAIL (not PASS, not INCONCLUSIVE): a cell whose currency has NO balance seal at all', async () => {
    setRegistry([{ label: 'EURS-ETH', chain: 'ethereum', contract: EUR_CONTRACT, decimals: 2, currency: 'EUR', reserveCurrency: 'EUR' }]);
    const world = makeWorld({
      sealSpecs: [{ provider: 'clearbank', currency: 'GBP', availableBalance: '1000000.00' }], // GBP evidence only
      ethSupplies: { [EUR_CONTRACT]: 100000000n }, // EUR 1m supply outstanding
      canonicalRecord: rec('ethereum-sepolia', EUR_CONTRACT, 'EUR'),
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /RESERVE_SHORTFALL\[EUR\]/.test(f.reason) && /No balance seal/.test(f.reason)),
      `expected an evidence-absent EUR shortfall, got: ${JSON.stringify(r.failures)}`);
  });
});

describe('finding 18 — mixed decimals inside a cell no longer throw', () => {
  test('2dp + 18dp tokens in one GBP cell verify correctly (pre-0.5.0 RangeError)', async () => {
    setRegistry([
      { label: 'GBPS-2dp', chain: 'ethereum', contract: GBP_CONTRACT, decimals: 2, currency: 'GBP', reserveCurrency: 'GBP' },
      { label: 'GBPS-18dp', chain: 'ethereum', contract: GBP18_CONTRACT, decimals: 18, currency: 'GBP', reserveCurrency: 'GBP' },
    ]);
    const world = makeWorld({
      sealSpecs: [{ provider: 'clearbank', currency: 'GBP', availableBalance: '1000000.00' }],
      ethSupplies: {
        [GBP_CONTRACT]: 50000000n,                  // £500,000.00 at 2dp
        [GBP18_CONTRACT]: 500000n * (10n ** 18n),  // £500,000 at 18dp
      },
      canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP'),
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC });
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures)} inconclusive: ${JSON.stringify(r.inconclusive)}`);
    const cell = r.stages.supply.cells[0];
    assert.equal(cell.decimals, 18); // cell decimals = max, so every rebase multiplies up
    assert.equal(cell.onChainSupplyMinorUnits, (1000000n * (10n ** 18n)).toString());
  });
});

describe('finding 19 — tolerance never crosses a cell boundary', () => {
  test("FAIL: an EUR token's tolerance must NOT absorb a GBP shortfall (pre-0.5.0 false PASS)", async () => {
    setRegistry([
      { label: 'EURS-ETH', chain: 'ethereum', contract: EUR_CONTRACT, decimals: 2, currency: 'EUR', reserveCurrency: 'EUR', toleranceMinorUnits: '100000000' },
      { label: 'GBPS-ETH', chain: 'ethereum', contract: GBP_CONTRACT, decimals: 2, currency: 'GBP', reserveCurrency: 'GBP' },
    ]);
    const world = makeWorld({
      sealSpecs: [
        { provider: 'clearbank', currency: 'EUR', availableBalance: '100.00' },
        { provider: 'clearbank', currency: 'GBP', availableBalance: '500000.00' },
      ],
      ethSupplies: { [EUR_CONTRACT]: 10000n, [GBP_CONTRACT]: 100000000n },
      canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP'),
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /RESERVE_SHORTFALL\[GBP\]/.test(f.reason)));
    const gbp = r.stages.supply.cells.find((c) => c.currency === 'GBP');
    assert.equal(gbp.toleranceMinorUnits, '0'); // the EUR token's tolerance stayed in the EUR cell
  });

  test('a tolerance declared inside the cell still applies to that cell', async () => {
    setRegistry([
      { label: 'GBPS-ETH', chain: 'ethereum', contract: GBP_CONTRACT, decimals: 2, currency: 'GBP', reserveCurrency: 'GBP', toleranceMinorUnits: '100' },
    ]);
    const world = makeWorld({
      sealSpecs: [{ provider: 'clearbank', currency: 'GBP', availableBalance: '999999.00' }], // £1.00 short
      ethSupplies: { [GBP_CONTRACT]: 100000000n },
      canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP'),
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC });
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures)}`); // within the £1.00 tolerance
  });
});

describe('protocol v3 — multi-bank witness generation', () => {
  test('a v3 witness (RFC-6962 tree + account-referenced seals) verifies end-to-end', async () => {
    setRegistry([{ label: 'GBPS-ETH', chain: 'ethereum', contract: GBP_CONTRACT, decimals: 2, currency: 'GBP', reserveCurrency: 'GBP' }]);
    const world = makeWorld({
      protocolVersion: 'v3',
      sealSpecs: [
        { provider: 'clearbank', currency: 'GBP', availableBalance: '600000.00', bankAccountId: 'cb-acct-1' },
        { provider: 'clearbank', currency: 'GBP', availableBalance: '400000.00', bankAccountId: 'cb-acct-2' },
      ],
      ethSupplies: { [GBP_CONTRACT]: 100000000n },
      canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP'),
    });
    const r = await verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC });
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures)} inconclusive: ${JSON.stringify(r.inconclusive)}`);
    assert.equal(r.stages.merkle.protocolVersion, 'v3');
  });
});
