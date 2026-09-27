/**
 * recordBinding.test.js — regression pins for the 2026-07-29 cell audit,
 * finding 12 (verifier side): the verdict must be bound to the cell named
 * by Memo 1 (`treasury-attestation-v1`) in the transaction being verified.
 *
 * Before v0.6.0, xrpl.js extracted the canonical record and index.js never
 * read it, so:
 *   - a GBP-cell tx and an EUR-cell tx returned byte-identical results,
 *     both driven by whichever cell tenants.json listed first;
 *   - a published verdict other than 'balanced' was silently ignored
 *     (an `out_of_tolerance` tx could print VERDICT: PASS);
 *   - a `combined` transaction was indistinguishable from a per-tuple one.
 *
 * Trust boundary pinned here too: the record's claimed figures are NEVER
 * inputs to the PASS/FAIL comparison — the reserve comes from the signed
 * seals, the supply from the chain. And v1 records (every tx anchored
 * 2026-05-23..2026-07-29) carry the literal 'null' for bank and delta:
 * that means "never committed", which is NOT zero and NOT an error.
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { buildCanonicalInput } from '../src/canonical.js';
import { computeMerkleRootForVersion, leafDigest } from '../src/merkle.js';
import { verify } from '../src/index.js';
import { parseCanonicalRecord, bindRecordToCell, SUPPORTED_CANONICAL_RECORD_VERSIONS, PUBLISHED_VERDICT_OVER_RESERVED } from '../src/attestationRecord.js';
import { renderHuman } from '../src/report.js';
import { _setForTests as setRegistryForTests, _resetForTests as resetRegistry } from '../src/tenantRegistry.js';

const TENANT = 'tvvin-binding';
const DATE = '2026-07-30';
const ENDPOINT = '/v1/balance';
const KID = 'projects/bipcircle/locations/europe-west2/keyRings/bank-service-signers/cryptoKeys/tvvin-binding-signer/cryptoKeyVersions/1';
const KID_PATTERN = '^projects/bipcircle/locations/europe-west2/keyRings/bank-service-signers/cryptoKeys/tvvin-binding-signer/cryptoKeyVersions/\\d+$';
const TXHASH = 'F'.repeat(64);
const BANK_URL = 'https://bank-service-binding.example';
const WITNESS_URL = `https://storage.googleapis.com/witnesses/${TENANT}/${DATE}.json`;
const ISSUER = 'rExampleIssuerAddress0000000000000000000';
const ETH_RPC = 'https://eth-rpc.example';

const EUR_CONTRACT = `0x${'aa'.repeat(20)}`;
const GBP_CONTRACT = `0x${'bb'.repeat(20)}`;
const UNKNOWN_CONTRACT = `0x${'dd'.repeat(20)}`;

const TOKENS = [
  { label: 'GBPS-ETH', chain: 'ethereum', contract: GBP_CONTRACT, decimals: 2, currency: 'GBP', reserveCurrency: 'GBP' },
  { label: 'EURS-ETH', chain: 'ethereum', contract: EUR_CONTRACT, decimals: 2, currency: 'EUR', reserveCurrency: 'EUR' },
];

function rec(chain, tokenKey, currency, {
  version = 'v2', verdict = 'balanced', asOfDate = DATE,
  onChain = 'null', ledger = 'null', bank = 'null', delta = 'null',
} = {}) {
  return [version, asOfDate, chain, tokenKey, currency, verdict, onChain, ledger, bank, delta,
    `${asOfDate}_${TENANT}_${chain}_${tokenKey}`].join('|');
}

/**
 * One signed world, two cells:
 *   GBP cell — reserves £500,000 vs supply £1,000,000  → genuinely SHORT
 *   EUR cell — reserves €10,000,000 vs supply €100     → healthy
 * canonicalRecord picks the Memo 1 published in the tx (null = omitted).
 */
function makeWorld({ canonicalRecord = null, gbpReserve = '500000.00' } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const sealSpecs = [
    { provider: 'clearbank', currency: 'GBP', availableBalance: gbpReserve },
    { provider: 'clearbank', currency: 'EUR', availableBalance: '10000000.00' },
  ];
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
  const sealMerkleRoot = computeMerkleRootForVersion(leaves, 'v2');
  const witness = { protocolVersion: 'v2', asOfDate: DATE, tenantId: TENANT, bankServicePublicKeyId: KID, sealMerkleRoot, sealCount: seals.length, seals };
  const witnessJson = JSON.stringify(witness);
  const witnessSha256 = crypto.createHash('sha256').update(witnessJson, 'utf8').digest('hex');
  const jwk = publicKey.export({ format: 'jwk' });
  const jwks = { keys: [{ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, use: 'sig', alg: 'ES256', kid: KID }] };
  const memo5 = { protocolVersion: 'v2', sealMerkleRoot, witnessSha256, bankServicePublicKeyId: KID, sealCount: seals.length, witnessUrl: WITNESS_URL };
  const hex = (s) => Buffer.from(s, 'utf8').toString('hex').toUpperCase();
  const memos = [
    ...(canonicalRecord ? [{ Memo: { MemoType: hex('treasury-attestation-v1'), MemoData: hex(canonicalRecord) } }] : []),
    { Memo: { MemoType: hex('reserve-verifier-v1'), MemoData: hex(JSON.stringify(memo5)) } },
  ];
  const xrplTx = { result: { Account: ISSUER, ledger_index: 12345, Memos: memos } };
  const ethSupplies = { [GBP_CONTRACT]: 100000000n, [EUR_CONTRACT]: 10000n }; // 2dp

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
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: `0x${(ethSupplies[to] ?? 0n).toString(16)}` }) };
    }
    return { ok: true, json: async () => xrplTx };
  };
  return { fetchImpl };
}

const run = (world, extra = {}) => verify({ txHash: TXHASH, tenantId: TENANT, fetchImpl: world.fetchImpl, ethRpcUrl: ETH_RPC, ...extra });

beforeEach(() => {
  resetRegistry();
  setRegistryForTests({ tenants: [{ tenantId: TENANT, bankServiceUrl: BANK_URL, xrplIssuerAddress: ISSUER, kidPattern: KID_PATTERN, tokens: TOKENS }] });
});

describe('finding 12.1 — the verdict is bound to the cell the transaction names', () => {
  test('GBP-cell tx → FAIL on the GBP shortfall; EUR-cell tx against the SAME evidence → PASS (no longer byte-identical)', async () => {
    const gbpWorld = makeWorld({ canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP') });
    const eurWorld = makeWorld({ canonicalRecord: rec('ethereum-sepolia', EUR_CONTRACT, 'EUR') });
    const rGbp = await run(gbpWorld);
    const rEur = await run(eurWorld);

    assert.equal(rGbp.verdict, 'FAIL');
    assert.equal(rGbp.stages.supply.verifiedCell, 'GBP');
    assert.ok(rGbp.failures.some((f) => /RESERVE_SHORTFALL\[GBP\]/.test(f.reason)));

    assert.equal(rEur.verdict, 'PASS', `EUR failures: ${JSON.stringify(rEur.failures)} inconclusive: ${JSON.stringify(rEur.inconclusive)}`);
    assert.equal(rEur.stages.supply.verifiedCell, 'EUR');
    assert.equal(rEur.stages.supply.cells.length, 1);

    assert.notDeepEqual(rGbp, rEur); // the pre-0.6.0 bug was byte-identical output
  });

  test('a missing Memo 1 can never PASS — every cell is still checked, so a shortfall anywhere still FAILs', async () => {
    // Healthy world, no record → INCONCLUSIVE (cannot bind, cannot PASS).
    const healthy = await run(makeWorld({ canonicalRecord: null, gbpReserve: '1000000.00' }));
    assert.equal(healthy.verdict, 'INCONCLUSIVE');
    assert.ok(healthy.inconclusive.some((f) => /CANONICAL_RECORD_MISSING/.test(f.reason)));
    assert.equal(healthy.stages.supply.verifiedCell, null);
    assert.equal(healthy.stages.supply.cells.length, 2); // unscoped fallback checked both cells

    // Short world, no record → the shortfall still surfaces as FAIL.
    const short = await run(makeWorld({ canonicalRecord: null }));
    assert.equal(short.verdict, 'FAIL');
    assert.ok(short.failures.some((f) => /RESERVE_SHORTFALL\[GBP\]/.test(f.reason)));
  });

  test('INCONCLUSIVE when the record names a token this registry does not pin (stale registry ≠ verified)', async () => {
    const r = await run(makeWorld({ canonicalRecord: rec('ethereum-sepolia', UNKNOWN_CONTRACT, 'GBP'), gbpReserve: '1000000.00' }));
    assert.equal(r.verdict, 'INCONCLUSIVE');
    assert.ok(r.inconclusive.some((f) => /TOKEN_NOT_IN_REGISTRY/.test(f.reason)));
    assert.equal(r.stages.supply.verifiedCell, null);
  });

  test('FAIL when the record and the pinned registry disagree about which cell a token belongs to', async () => {
    // Record claims the GBP contract belongs to the EUR cell.
    const r = await run(makeWorld({ canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'EUR'), gbpReserve: '1000000.00' }));
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /CELL_BINDING_MISMATCH/.test(f.reason)),
      `expected CELL_BINDING_MISMATCH, got: ${JSON.stringify(r.failures)}`);
  });

  test('FAIL when the record and the witness in one tx disagree on the business date', async () => {
    const r = await run(makeWorld({ canonicalRecord: rec('ethereum-sepolia', EUR_CONTRACT, 'EUR', { asOfDate: '2026-07-29' }) }));
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /RECORD_WITNESS_DATE_MISMATCH/.test(f.reason)));
  });
});

describe('finding 12.2 — a published non-balanced verdict never yields a quiet PASS', () => {
  test("FAIL: published 'out_of_tolerance' surfaces even when today's independent re-derivation is clean", async () => {
    const r = await run(makeWorld({
      canonicalRecord: rec('ethereum-sepolia', EUR_CONTRACT, 'EUR', { verdict: 'out_of_tolerance', bank: '10.0', delta: '90' }),
      gbpReserve: '1000000.00',
    }));
    assert.equal(r.verdict, 'FAIL'); // pre-0.6.0: quiet PASS
    assert.ok(r.failures.some((f) => /PUBLISHED_VERDICT_DRIFT.*out_of_tolerance/.test(f.reason)));
  });

  test("FAIL: published 'partial_drift' is detected drift", async () => {
    const r = await run(makeWorld({ canonicalRecord: rec('ethereum-sepolia', EUR_CONTRACT, 'EUR', { verdict: 'partial_drift' }) }));
    assert.ok(r.failures.some((f) => /PUBLISHED_VERDICT_DRIFT/.test(f.reason)));
    assert.equal(r.verdict, 'FAIL');
  });

  test("INCONCLUSIVE: published 'provider_unavailable' / 'partial_balanced' / unknown verdict tokens (issuer's own record disclaims full coverage)", async () => {
    for (const verdict of ['provider_unavailable', 'partial_balanced', 'some_future_verdict']) {
      const r = await run(makeWorld({
        canonicalRecord: rec('ethereum-sepolia', EUR_CONTRACT, 'EUR', { verdict }),
        gbpReserve: '1000000.00',
      }));
      assert.equal(r.verdict, 'INCONCLUSIVE', `verdict '${verdict}' must not PASS`);
      assert.ok(r.inconclusive.some((f) => new RegExp(`PUBLISHED_VERDICT_NOT_BALANCED.*'${verdict}'`).test(f.reason)));
    }
  });
});

describe('finding 12.3 — a combined transaction is labelled and verified as the whole cell, never silently treated as per-tuple', () => {
  test("chain === 'combined' → reportClass 'combined', verified as the named cell", async () => {
    const r = await run(makeWorld({ canonicalRecord: rec('combined', 'combined:eur', 'EUR'), gbpReserve: '1000000.00' }));
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures)} inconclusive: ${JSON.stringify(r.inconclusive)}`);
    assert.equal(r.stages.record.reportClass, 'combined');
    assert.equal(r.stages.supply.reportClass, 'combined');
    assert.equal(r.stages.supply.verifiedCell, 'EUR');
  });

  test('a combined row for a SHORT cell FAILs on that cell', async () => {
    const r = await run(makeWorld({ canonicalRecord: rec('combined', 'combined:gbp', 'GBP') }));
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /RESERVE_SHORTFALL\[GBP\]/.test(f.reason)));
    assert.equal(r.stages.supply.verifiedCell, 'GBP');
  });

  test('INCONCLUSIVE when a combined row names a cell with no pinned tokens', async () => {
    const r = await run(makeWorld({ canonicalRecord: rec('combined', 'combined:usd', 'USD'), gbpReserve: '1000000.00' }));
    assert.equal(r.verdict, 'INCONCLUSIVE');
    assert.ok(r.inconclusive.some((f) => /NAMED_CELL_NOT_IN_REGISTRY/.test(f.reason)));
  });
});

describe('trust boundary — the record is a claim, never an input to the comparison', () => {
  test("FAIL: a v2 record CLAIMING full backing cannot rescue a real shortfall (reserve comes from the seals, not the record)", async () => {
    const r = await run(makeWorld({
      // Record claims bank reserve of £1,000,000 and 'balanced' — but the
      // signed seals only prove £500,000 against £1,000,000 of supply.
      canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP', { onChain: '1000000.0', ledger: '1000000.0', bank: '1000000.0', delta: '0' }),
    }));
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /RESERVE_SHORTFALL\[GBP\]/.test(f.reason)));
    // The derived figure is the seal sum, untouched by the record's claim.
    assert.equal(r.stages.supply.cells[0].reservesMinorUnits, '50000000');
  });

  test("v1 record: 'null' bank/delta = never committed — verifies fine, is not treated as zero, is not an error", async () => {
    const r = await run(makeWorld({
      canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP', { version: 'v1', onChain: '1000000.0', ledger: '1000000.0' }),
      gbpReserve: '1000000.00',
    }));
    // If 'null' were coerced to a zero reserve claim this could not PASS.
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures)} inconclusive: ${JSON.stringify(r.inconclusive)}`);
    assert.equal(r.stages.record.version, 'v1');
    assert.equal(r.stages.record.claimed.bank, null);
    assert.equal(r.stages.record.claimed.delta, null);
    assert.deepEqual(r.stages.record.committed, { bank: false, delta: false });
  });
});

describe('canonical-record version discipline (SUPPORTED_CANONICAL_RECORD_VERSIONS is the fail-closed lever)', () => {
  test('exactly v1 and v2 are supported today', () => {
    assert.deepEqual([...SUPPORTED_CANONICAL_RECORD_VERSIONS].sort(), ['v1', 'v2']);
  });

  test('an unknown record version → INCONCLUSIVE ("upgrade the verifier"), never PASS, never a partial read', async () => {
    const raw = rec('ethereum-sepolia', GBP_CONTRACT, 'GBP').replace(/^v2/, 'v9');
    const r = await run(makeWorld({ canonicalRecord: raw, gbpReserve: '1000000.00' }));
    assert.equal(r.verdict, 'INCONCLUSIVE');
    assert.ok(r.inconclusive.some((f) => /RECORD_VERSION_UNSUPPORTED/.test(f.reason) && /upgrade/i.test(f.reason)));
  });

  test('a malformed record (wrong field count) → INCONCLUSIVE, and cells are still checked', async () => {
    const r = await run(makeWorld({ canonicalRecord: `v2|${DATE}|ethereum-sepolia|only-four-fields` }));
    assert.ok(r.inconclusive.some((f) => /RECORD_MALFORMED/.test(f.reason)));
    // Short GBP world: the unscoped fallback still finds the shortfall.
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /RESERVE_SHORTFALL\[GBP\]/.test(f.reason)));
  });
});

describe("published 'over_reserved' (BIPCircle D-183): a disclosed surplus, held to the verifier's own reserve check", () => {
  const OVER = { verdict: 'over_reserved', onChain: '100.00', ledger: '100.00', bank: '10000000.00', delta: '9999900.00' };

  test('the verdict token is recognised', () => {
    assert.equal(PUBLISHED_VERDICT_OVER_RESERVED, 'over_reserved');
  });

  test('PASS when the verifier itself finds reserves >= supply; the claim is neither drift nor inconclusive', async () => {
    const r = await run(makeWorld({ canonicalRecord: rec('ethereum-sepolia', EUR_CONTRACT, 'EUR', OVER) }));
    assert.equal(r.verdict, 'PASS', `failures: ${JSON.stringify(r.failures)} inconclusive: ${JSON.stringify(r.inconclusive)}`);
    assert.equal(r.stages.record.verdict, 'over_reserved');
    assert.ok(!r.failures.some((f) => /PUBLISHED_VERDICT_DRIFT/.test(f.reason)));
    assert.ok(!r.inconclusive.some((f) => /PUBLISHED_VERDICT_NOT_BALANCED/.test(f.reason)));
    const over = r.stages.record.overReserved;
    assert.equal(over.declared, true);
    assert.equal(over.declaredSurplus, '9999900.00');
    assert.equal(over.verified, true);
    assert.equal(over.verifiedDeltaMinorUnits, '999990000'); // €10,000,000.00 - €100.00 at 2dp
  });

  test('PASS at exactly level: reserves == supply is not a shortfall', async () => {
    const r = await run(makeWorld({ canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP', OVER), gbpReserve: '1000000.00' }));
    assert.equal(r.verdict, 'PASS', JSON.stringify(r.failures));
    assert.equal(r.stages.record.overReserved.verifiedDeltaMinorUnits, '0');
  });

  test('FAIL when the verifier finds a shortfall — the surplus claim is contradicted', async () => {
    const r = await run(makeWorld({ canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP', OVER) }));
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /RESERVE_SHORTFALL\[GBP\]/.test(f.reason)));
    assert.ok(r.failures.some((f) => /PUBLISHED_OVER_RESERVED_CONTRADICTED/.test(f.reason)));
    assert.equal(r.stages.record.overReserved.verified, false);
  });

  test('FAIL on a shortfall INSIDE the cell tolerance: the tolerance never turns a deficit into a surplus', async () => {
    resetRegistry();
    setRegistryForTests({ tenants: [{ tenantId: TENANT, bankServiceUrl: BANK_URL, xrplIssuerAddress: ISSUER, kidPattern: KID_PATTERN,
      tokens: [{ ...TOKENS[0], toleranceMinorUnits: '100000' }, TOKENS[1]] }] });
    const world = makeWorld({ canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP', OVER), gbpReserve: '999999.00' });
    const r = await run(world);
    assert.equal(r.stages.supply.cells[0].ok, true, 'CONTROL: the shortfall is inside tolerance, so the plain supply check passes');
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.failures.some((f) => /PUBLISHED_OVER_RESERVED_CONTRADICTED/.test(f.reason)));
    // The same world with a balanced record passes: the extra FAIL is the surplus claim's alone.
    const balanced = await run(makeWorld({ canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP'), gbpReserve: '999999.00' }));
    assert.equal(balanced.verdict, 'PASS', JSON.stringify(balanced.failures));
  });

  test('INCONCLUSIVE when the verifier did not run its own reserve check', async () => {
    const r = await run(makeWorld({ canonicalRecord: rec('ethereum-sepolia', EUR_CONTRACT, 'EUR', OVER) }), { skipOnChainSupply: true });
    assert.equal(r.verdict, 'INCONCLUSIVE');
    assert.ok(r.inconclusive.some((f) => /PUBLISHED_OVER_RESERVED_UNVERIFIED/.test(f.reason)));
    assert.equal(r.stages.record.overReserved.verified, null);
  });

  test('the report prints the declared surplus, the claimed figures and what the verifier found', async () => {
    const r = await run(makeWorld({ canonicalRecord: rec('ethereum-sepolia', EUR_CONTRACT, 'EUR', OVER) }));
    const out = renderHuman(r, { network: 'testnet', txHash: TXHASH });
    assert.match(out, /published verdict:\s+over_reserved/);
    assert.match(out, /claimed bank:\s+10000000\.00 EUR/);
    assert.match(out, /declared surplus:\s+9999900\.00 EUR \(issuer declares reserves ABOVE liabilities; not drift\)/);
    assert.match(out, /verified surplus:\s+€9,999,900\.00/);
    const bad = await run(makeWorld({ canonicalRecord: rec('ethereum-sepolia', GBP_CONTRACT, 'GBP', OVER) }));
    assert.match(renderHuman(bad, { network: 'testnet', txHash: TXHASH }), /verified surplus:\s+CONTRADICTED/);
  });
});

describe('unit: parseCanonicalRecord + bindRecordToCell', () => {
  test('parses a REAL anchored v1 record (tx 7753CF92…, XRPL testnet, 2026-05-25)', () => {
    // Byte-for-byte the Memo 1 payload of the first recorded PASS tx.
    const raw = 'v1|2026-05-25|ethereum-sepolia|0xdc48900756db73d795cd5c9fcb6caabe33de27c4|GBP|balanced|0.0|0|null|null|2026-05-25_tvvin_ethereum-sepolia_0xdc48900756db73d795cd5c9fcb6caabe33de27c4';
    const rec1 = parseCanonicalRecord(raw);
    assert.equal(rec1.version, 'v1');
    assert.equal(rec1.currency, 'GBP');
    assert.equal(rec1.verdict, 'balanced');
    assert.equal(rec1.reportClass, 'per-tuple');
    assert.equal(rec1.claimed.onChain, '0.0'); // committed as zero — a REAL claim
    assert.equal(rec1.claimed.bank, null);     // never committed — NOT zero
  });

  test('binds an XRPL tokenKey (`fiat.issuer`) through reserveCurrency, never through the on-ledger ticker', () => {
    const tokens = [{ label: 'TVV-XRPL', chain: 'xrpl', issuer: ISSUER, currency: 'TVV', decimals: 0, reserveCurrency: 'GBP' }];
    const record = parseCanonicalRecord(rec('xrpl-testnet', `gbp.${ISSUER}`, 'GBP'));
    const bind = bindRecordToCell(record, tokens);
    assert.deepEqual(bind, { ok: true, cellCurrency: 'GBP' });
    // Unknown issuer → not in registry.
    const unknown = parseCanonicalRecord(rec('xrpl-testnet', 'gbp.rSomeOtherIssuer111111111111111111', 'GBP'));
    assert.equal(bindRecordToCell(unknown, tokens).code, 'TOKEN_NOT_IN_REGISTRY');
  });
});
