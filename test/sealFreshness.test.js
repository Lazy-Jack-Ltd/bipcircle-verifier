// POR-SEAL-FRESHNESS-01 regression pin (2026-07-07).
//
// The verifier ECDSA-verifies each seal's canonicalInput but previously never
// gated the seal's SIGNED timestamp to the witness asOfDate, and never checked the
// seal's endpoint. Because on-chain supply is read LIVE and asOfDate is
// operator-set/unsigned, a genuine balance seal from ANY past instant could be
// replayed under today's witness to back a live supply — the attest-then-drain-
// then-replay attack an independent proof-of-reserves exists to defeat. This suite
// pins the fix: a stale seal, a wrong-endpoint seal, and a timestamp-less seal are
// all rejected when freshness is enforced.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sumBankReserves } from '../src/onchain.js';

function balanceSeal({ eventId, signedAt, provider = 'starling', currency = 'GBP', availableBalance, asOf, endpoint = '/v1/balance' }) {
  const payload = { type: 'balance', endpoint, provider, currency, availableBalance, asOf };
  return {
    eventId,
    signedAt,
    canonicalInput: Buffer.from(JSON.stringify(payload), 'utf8').toString('base64'),
  };
}

test('POR-SEAL-FRESHNESS-01: fresh same-day seal within the window is summed', () => {
  const seals = [balanceSeal({ eventId: 'e1', signedAt: '2026-07-07T09:00:00Z', availableBalance: '1000000.00', asOf: '2026-07-07T09:00:00Z' })];
  assert.equal(
    sumBankReserves(seals, 2, 'GBP', { asOfDate: '2026-07-07', maxSealAgeHours: 48, expectedEndpoint: '/v1/balance' }),
    100000000n,
  );
});

test('POR-SEAL-FRESHNESS-01: STALE seal (attest-then-drain-then-replay) is REJECTED', () => {
  // A genuine £1m seal from ~5 weeks ago, replayed under today's witness asOfDate
  // while the account has since been drained. Must NOT count as a current reserve.
  const seals = [balanceSeal({ eventId: 'e1', signedAt: '2026-06-01T09:00:00Z', availableBalance: '1000000.00', asOf: '2026-06-01T09:00:00Z' })];
  assert.throws(
    () => sumBankReserves(seals, 2, 'GBP', { asOfDate: '2026-07-07', maxSealAgeHours: 48 }),
    /POR-SEAL-FRESHNESS-01/,
  );
});

test('POR-SEAL-FRESHNESS-01: seal from a non-balance endpoint is REJECTED', () => {
  const seals = [balanceSeal({ eventId: 'e1', signedAt: '2026-07-07T09:00:00Z', availableBalance: '1000000.00', asOf: '2026-07-07T09:00:00Z', endpoint: '/v1/statements' })];
  assert.throws(
    () => sumBankReserves(seals, 2, 'GBP', { asOfDate: '2026-07-07', expectedEndpoint: '/v1/balance' }),
    /POR-SEAL-FRESHNESS-01/,
  );
});

test('POR-SEAL-FRESHNESS-01: seal with no parseable timestamp is REJECTED when freshness enforced', () => {
  const seals = [balanceSeal({ eventId: 'e1', signedAt: 'not-a-date', availableBalance: '1000000.00', asOf: '' })];
  assert.throws(
    () => sumBankReserves(seals, 2, 'GBP', { asOfDate: '2026-07-07' }),
    /POR-SEAL-FRESHNESS-01/,
  );
});

test('POR-SEAL-FRESHNESS-01: day-boundary seal (within 48h window) still passes', () => {
  // Seal signed just before midnight UTC on asOfDate-1, witness asOfDate the next
  // day — legitimate cadence/timezone slack, within the 48h window.
  const seals = [balanceSeal({ eventId: 'e1', signedAt: '2026-07-06T23:30:00Z', availableBalance: '1000000.00', asOf: '2026-07-06T23:30:00Z' })];
  assert.equal(
    sumBankReserves(seals, 2, 'GBP', { asOfDate: '2026-07-07', maxSealAgeHours: 48, expectedEndpoint: '/v1/balance' }),
    100000000n,
  );
});

test('back-compat: no asOfDate → freshness gate skipped (existing 3-arg callers unaffected)', () => {
  const seals = [balanceSeal({ eventId: 'e1', signedAt: '2020-01-01T00:00:00Z', availableBalance: '1000000.00', asOf: '2020-01-01T00:00:00Z' })];
  assert.equal(sumBankReserves(seals, 2, 'GBP'), 100000000n);
});
