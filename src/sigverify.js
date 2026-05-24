/**
 * sigverify.js — ECDSA P-256 verification of each seal entry in the
 * witness file.
 *
 * For each seal:
 *   1. Decode the canonical-input base64 → bytes.
 *   2. Decode the signature base64 → DER bytes.
 *   3. Look up the public key by seal.publicKeyId in the JWKS map.
 *   4. crypto.verify('sha256', canonicalBytes, key, signature) — Node's
 *      built-in ECDSA verification. dsaEncoding='der' matches bank-
 *      service's signing.
 *   5. Compare the leaf digest SHA-256(canonical-input) to its
 *      ordered position in the Merkle leaf list; the Merkle root
 *      comparison is done separately in verify.js.
 *
 * Returns: a result object listing each seal's verify outcome.
 * Throws ONLY for structural failures (missing kid, malformed
 * signature). Crypto failures are reported in the result, not
 * thrown — the verifier wants to surface ALL bad seals, not just
 * the first.
 */

'use strict';

import crypto from 'node:crypto';

import { leafDigest } from './merkle.js';

export function verifySealSignatures({ witnessSeals, jwksByKid }) {
  const results = [];
  const leaves = [];
  for (const seal of witnessSeals) {
    const canonicalBytes = Buffer.from(seal.canonicalInput, 'base64');
    const signatureBytes = Buffer.from(seal.signature, 'base64');
    const key = jwksByKid.get(seal.publicKeyId);
    if (!key) {
      results.push({
        eventId: seal.eventId,
        publicKeyId: seal.publicKeyId,
        ok: false,
        reason: `KID_NOT_IN_JWKS: '${seal.publicKeyId}' not found in advertised keys (rotation gap or wrong bank-service URL?)`,
      });
      leaves.push(leafDigest(canonicalBytes));
      continue;
    }
    let ok = false;
    let reason = null;
    try {
      ok = crypto.verify(
        'sha256',
        canonicalBytes,
        { key, dsaEncoding: 'der' },
        signatureBytes,
      );
      if (!ok) reason = 'ECDSA_VERIFY_FAILED: signature does not match canonical input for this public key';
    } catch (err) {
      reason = `ECDSA_VERIFY_ERROR: ${err.message}`;
    }
    results.push({
      eventId: seal.eventId,
      publicKeyId: seal.publicKeyId,
      ok,
      reason,
    });
    leaves.push(leafDigest(canonicalBytes));
  }
  return { results, leaves };
}
