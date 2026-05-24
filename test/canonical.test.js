import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { buildCanonicalInput } from '../src/canonical.js';

describe('buildCanonicalInput', () => {
  test('alphabetical top-level key ordering is deterministic', () => {
    const a = buildCanonicalInput({
      payload: { x: 1, y: 2 }, tenantId: 't', eventId: 'e', signedAt: 's', endpoint: '/v1/balance',
    });
    const b = buildCanonicalInput({
      endpoint: '/v1/balance', tenantId: 't', signedAt: 's', eventId: 'e', payload: { y: 2, x: 1 },
    });
    assert.equal(a, b);
  });

  test('different endpoints → different canonical (cross-endpoint replay defence)', () => {
    const bal = buildCanonicalInput({ payload: { x: 1 }, tenantId: 't', eventId: 'e', signedAt: 's', endpoint: '/v1/balance' });
    const pay = buildCanonicalInput({ payload: { x: 1 }, tenantId: 't', eventId: 'e', signedAt: 's', endpoint: '/v1/payment' });
    assert.notEqual(bal, pay);
  });

  test('rejects missing required fields', () => {
    assert.throws(() => buildCanonicalInput({ payload: {}, tenantId: '', eventId: 'e', signedAt: 's', endpoint: '/v1/balance' }), /tenantId is required/);
    assert.throws(() => buildCanonicalInput({ payload: {}, tenantId: 't', eventId: '', signedAt: 's', endpoint: '/v1/balance' }), /eventId is required/);
    assert.throws(() => buildCanonicalInput({ payload: {}, tenantId: 't', eventId: 'e', signedAt: '', endpoint: '/v1/balance' }), /signedAt is required/);
    assert.throws(() => buildCanonicalInput({ payload: {}, tenantId: 't', eventId: 'e', signedAt: 's', endpoint: '' }), /endpoint is required/);
  });

  test('byte-identical to producer canonicalisation (algorithm pin)', () => {
    // This is the spec example from the protocol doc — if it changes,
    // the bank-service producer side has drifted from the verifier.
    const out = buildCanonicalInput({
      payload: { availableBalance: '1000.00', currency: 'GBP', type: 'balance', provider: 'mock' },
      tenantId: 'tvvin-prod',
      eventId: '00000000-0000-4000-8000-000000000001',
      signedAt: '2026-05-24T10:00:00.000Z',
      endpoint: '/v1/balance',
    });
    // Top-level keys in sorted order: availableBalance, currency,
    // endpoint, eventId, provider, signedAt, tenantId, type
    assert.equal(
      out,
      '{"availableBalance":"1000.00","currency":"GBP","endpoint":"/v1/balance","eventId":"00000000-0000-4000-8000-000000000001","provider":"mock","signedAt":"2026-05-24T10:00:00.000Z","tenantId":"tvvin-prod","type":"balance"}',
    );
  });
});
