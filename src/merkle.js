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
 * Hardened v2 Merkle root — RFC-6962-style domain separation. Byte-identical
 * to BIPCircle's sealMerkle.js computeMerkleRootV2. Unlike v1 it cannot be made
 * malleable by odd-leaf duplication (CVE-2012-2459) or leaf-vs-internal
 * confusion (POR-MERKLE-V1-MALLEABLE-02):
 *   - leaf node = sha256(0x00 || leafDigest)    (leaf domain tag)
 *   - internal  = sha256(0x01 || left || right) (internal domain tag)
 *   - an odd node is promoted UNCHANGED, never duplicated
 *
 * Dispatched on witness.protocolVersion: 'v2' uses this; v1/absent uses
 * computeMerkleRoot above (so already-published v1 witnesses still verify).
 *
 * @param {string[]} leafHexDigests — hex strings (64 chars each)
 * @returns {string|null} 64-char hex root, or null for empty input
 */
export function computeMerkleRootV2(leafHexDigests) {
  if (!Array.isArray(leafHexDigests) || leafHexDigests.length === 0) {
    return null;
  }
  const LEAF_TAG = Buffer.from([0x00]);
  const NODE_TAG = Buffer.from([0x01]);
  let layer = leafHexDigests.map((h) =>
    crypto.createHash('sha256').update(LEAF_TAG).update(Buffer.from(h, 'hex')).digest());
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      if (i + 1 < layer.length) {
        next.push(crypto.createHash('sha256').update(NODE_TAG).update(layer[i]).update(layer[i + 1]).digest());
      } else {
        next.push(layer[i]); // promote unchanged — never duplicate (closes CVE-2012-2459)
      }
    }
    layer = next;
  }
  return layer[0].toString('hex');
}

/**
 * Dispatch the right Merkle algorithm for a witness's protocolVersion.
 * 'v2' → computeMerkleRootV2 (RFC-6962); anything else (v1 / absent) → v1.
 * Centralised so index.js and any future caller cannot drift.
 *
 * @param {string[]} leafHexDigests
 * @param {string|undefined} protocolVersion — witness.protocolVersion
 * @returns {string|null}
 */
export function computeMerkleRootForVersion(leafHexDigests, protocolVersion) {
  return protocolVersion === 'v2'
    ? computeMerkleRootV2(leafHexDigests)
    : computeMerkleRoot(leafHexDigests);
}

/**
 * SHA-256 hex digest of canonical-input bytes — the leaf shape the
 * protocol uses.
 */
export function leafDigest(canonicalInputBytes) {
  return crypto.createHash('sha256').update(canonicalInputBytes).digest('hex');
}
