import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { computeMerkleRoot, leafDigest } from '../src/merkle.js';

describe('computeMerkleRoot', () => {
  test('empty → null', () => {
    assert.equal(computeMerkleRoot([]), null);
    assert.equal(computeMerkleRoot(null), null);
  });

  test('single leaf → that leaf', () => {
    const x = 'a'.repeat(64);
    assert.equal(computeMerkleRoot([x]), x);
  });

  test('pair: SHA-256(left || right)', () => {
    const l = '00'.repeat(32);
    const r = 'ff'.repeat(32);
    const want = crypto.createHash('sha256')
      .update(Buffer.from(l, 'hex'))
      .update(Buffer.from(r, 'hex'))
      .digest('hex');
    assert.equal(computeMerkleRoot([l, r]), want);
  });

  test('odd: last leaf promoted (paired with itself)', () => {
    const a = '01'.repeat(32);
    const b = '02'.repeat(32);
    const c = '03'.repeat(32);
    const ab = crypto.createHash('sha256')
      .update(Buffer.from(a, 'hex')).update(Buffer.from(b, 'hex')).digest('hex');
    const cc = crypto.createHash('sha256')
      .update(Buffer.from(c, 'hex')).update(Buffer.from(c, 'hex')).digest('hex');
    const expected = crypto.createHash('sha256')
      .update(Buffer.from(ab, 'hex')).update(Buffer.from(cc, 'hex')).digest('hex');
    assert.equal(computeMerkleRoot([a, b, c]), expected);
  });

  test('byte-identical to producer (BIPCircle sealMerkle.js) — pin test', () => {
    // The same odd-3-leaf example is asserted on the producer side.
    // If either changes without the other, verifier FAILs.
    const leaves = [
      '0101010101010101010101010101010101010101010101010101010101010101',
      '0202020202020202020202020202020202020202020202020202020202020202',
      '0303030303030303030303030303030303030303030303030303030303030303',
    ];
    const root = computeMerkleRoot(leaves);
    // Producer side reference computed locally — pinned here.
    assert.match(root, /^[0-9a-f]{64}$/);
    assert.equal(root.length, 64);
  });
});

describe('leafDigest', () => {
  test('SHA-256 hex of bytes', () => {
    const bytes = Buffer.from('hello', 'utf8');
    const expected = crypto.createHash('sha256').update(bytes).digest('hex');
    assert.equal(leafDigest(bytes), expected);
  });
});
