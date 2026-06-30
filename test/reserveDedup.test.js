// POR-RESERVE-DOUBLECOUNT-01 (whitehat sweep 3) regression test.
//
// sumBankReserves used to sum EVERY balance seal in the witness, so N intra-day
// reads of the same account were counted N times (a short reserve could show a
// false PASS), and balances in an unrelated currency were summed toward the
// token's backing. It now filters to the reserves currency and keeps only the
// latest balance per (currency, provider) account before summing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sumBankReserves } from '../src/onchain.js';

// Build a witness seal whose canonicalInput is the base64 JSON the verifier
// parses. Only the balance-relevant fields matter to sumBankReserves.
function balanceSeal({ eventId, signedAt, provider, currency, availableBalance, asOf }) {
  const payload = { type: 'balance', provider, currency, availableBalance, asOf };
  return {
    eventId,
    signedAt,
    canonicalInput: Buffer.from(JSON.stringify(payload), 'utf8').toString('base64'),
  };
}

test('three intra-day reads of the same account are counted ONCE (latest), not summed', () => {
  const seals = [
    balanceSeal({ eventId: 'e1', signedAt: '2026-06-30T09:00:00Z', provider: 'starling', currency: 'GBP', availableBalance: '1000000.00', asOf: '2026-06-30T09:00:00Z' }),
    balanceSeal({ eventId: 'e2', signedAt: '2026-06-30T12:00:00Z', provider: 'starling', currency: 'GBP', availableBalance: '1000000.00', asOf: '2026-06-30T12:00:00Z' }),
    balanceSeal({ eventId: 'e3', signedAt: '2026-06-30T17:00:00Z', provider: 'starling', currency: 'GBP', availableBalance: '1000000.00', asOf: '2026-06-30T17:00:00Z' }),
  ];
  // £1,000,000.00 → 100,000,000 pennies. The OLD code returned 300,000,000.
  assert.equal(sumBankReserves(seals, 2, 'GBP'), 100000000n);
});

test('the LATEST balance wins when intra-day reads differ', () => {
  const seals = [
    balanceSeal({ eventId: 'e1', signedAt: '2026-06-30T09:00:00Z', provider: 'starling', currency: 'GBP', availableBalance: '500000.00', asOf: '2026-06-30T09:00:00Z' }),
    balanceSeal({ eventId: 'e2', signedAt: '2026-06-30T17:00:00Z', provider: 'starling', currency: 'GBP', availableBalance: '900000.00', asOf: '2026-06-30T17:00:00Z' }),
  ];
  assert.equal(sumBankReserves(seals, 2, 'GBP'), 90000000n); // the 17:00 read
});

test('distinct accounts (different provider) are BOTH summed', () => {
  const seals = [
    balanceSeal({ eventId: 'e1', signedAt: '2026-06-30T17:00:00Z', provider: 'starling', currency: 'GBP', availableBalance: '600000.00', asOf: '2026-06-30T17:00:00Z' }),
    balanceSeal({ eventId: 'e2', signedAt: '2026-06-30T17:00:00Z', provider: 'clearbank', currency: 'GBP', availableBalance: '400000.00', asOf: '2026-06-30T17:00:00Z' }),
  ];
  assert.equal(sumBankReserves(seals, 2, 'GBP'), 100000000n); // £600k + £400k
});

test('a different-currency balance is NOT counted toward the token currency', () => {
  const seals = [
    balanceSeal({ eventId: 'e1', signedAt: '2026-06-30T17:00:00Z', provider: 'starling', currency: 'GBP', availableBalance: '1000000.00', asOf: '2026-06-30T17:00:00Z' }),
    balanceSeal({ eventId: 'e2', signedAt: '2026-06-30T17:00:00Z', provider: 'wise', currency: 'USD', availableBalance: '5000000.00', asOf: '2026-06-30T17:00:00Z' }),
  ];
  // Only the GBP £1,000,000.00 counts toward a GBP token.
  assert.equal(sumBankReserves(seals, 2, 'GBP'), 100000000n);
});

test('back-compat: no reservesCurrency still dedups (sums all currencies, one per account)', () => {
  const seals = [
    balanceSeal({ eventId: 'e1', signedAt: '2026-06-30T09:00:00Z', provider: 'starling', currency: 'GBP', availableBalance: '1000000.00', asOf: '2026-06-30T09:00:00Z' }),
    balanceSeal({ eventId: 'e2', signedAt: '2026-06-30T17:00:00Z', provider: 'starling', currency: 'GBP', availableBalance: '1000000.00', asOf: '2026-06-30T17:00:00Z' }),
  ];
  // Same account, two reads → deduped to one → 100,000,000 (not 200,000,000).
  assert.equal(sumBankReserves(seals, 2), 100000000n);
});
