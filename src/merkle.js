/**
 * merkle.js — byte-identical Merkle root computation to BIPCircle's
 * sealMerkle.js. SHA-256 over sorted leaf digests with odd-leaf
 * promotion (last odd leaf paired with itself).
 *
 * Verifiers MUST use this exact algorithm — any drift produces
 * false-FAIL verdicts. The shape is pinned by the public-reserve-
 * verifier-protocol.md specification in the BIPCircle repo.
 */

'use strict';

import crypto from 'node:crypto';

/**
 * @param {string[]} leafHexDigests — hex strings (64 chars each)
 * @returns {string|null} 64-char hex root, or null for empty input
 */
export function computeMerkleRoot(leafHexDigests) {
  if (!Array.isArray(leafHexDigests) || leafHexDigests.length === 0) {
    return null;
  }
  let layer = leafHexDigests.map((h) => Buffer.from(h, 'hex'));
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i]; // odd promotion
      const parent = crypto.createHash('sha256').update(left).update(right).digest();
      next.push(parent);
    }
    layer = next;
  }
  return layer[0].toString('hex');
}

/**
 * SHA-256 hex digest of canonical-input bytes — the leaf shape the
 * protocol uses.
 */
export function leafDigest(canonicalInputBytes) {
  return crypto.createHash('sha256').update(canonicalInputBytes).digest('hex');
}
