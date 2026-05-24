/**
 * witness.js — fetch + validate the witness JSON file.
 *
 * 1. HTTPS GET the witnessUrl (public bucket, no auth).
 * 2. Compute SHA-256 of the raw bytes; compare to witnessSha256 from
 *    the XRPL memo. Mismatch = FAIL (object tampered or wrong URL).
 * 3. Parse JSON. Validate schema (structural). Mismatch = FAIL.
 * 4. Verify the witness's claimed sealMerkleRoot matches the XRPL
 *    memo's anchored root (cross-check; both should be derived from
 *    the same seal set).
 */

'use strict';

import crypto from 'node:crypto';

const PROTOCOL_VERSION = 'v1';
// Self-audit (v0.1.1): bounded fetch — witness files are operator-
// hosted but cold or rate-limited GCS responses must not hang the
// verifier. 30s gives slack for slow regional fetches.
const DEFAULT_FETCH_TIMEOUT_MS = 30000;

export async function fetchAndValidateWitness({ witnessUrl, expectedWitnessSha256, expectedMerkleRoot, fetchImpl = fetch, timeoutMs = DEFAULT_FETCH_TIMEOUT_MS }) {
  if (typeof witnessUrl !== 'string' || !witnessUrl.startsWith('https://')) {
    throw new Error(`fetchAndValidateWitness: witnessUrl must be https://, got '${witnessUrl}'`);
  }
  if (typeof expectedWitnessSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(expectedWitnessSha256)) {
    throw new Error(`fetchAndValidateWitness: expectedWitnessSha256 must be 64-char lower-hex`);
  }
  if (typeof expectedMerkleRoot !== 'string' || !/^[0-9a-f]{64}$/.test(expectedMerkleRoot)) {
    throw new Error(`fetchAndValidateWitness: expectedMerkleRoot must be 64-char lower-hex`);
  }

  const res = await fetchImpl(witnessUrl, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) {
    throw new Error(`fetchAndValidateWitness: HTTP ${res.status} from ${witnessUrl}`);
  }
  const bytes = Buffer.from(await res.arrayBuffer());
  const actualSha = crypto.createHash('sha256').update(bytes).digest('hex');
  if (actualSha !== expectedWitnessSha256) {
    throw new Error(
      `WITNESS_TAMPERED: SHA-256 mismatch (expected ${expectedWitnessSha256}, got ${actualSha}). ` +
      `The bytes returned by ${witnessUrl} do not match what was anchored on XRPL — possible tampering or wrong URL.`,
    );
  }

  let witness;
  try {
    witness = JSON.parse(bytes.toString('utf8'));
  } catch (err) {
    throw new Error(`WITNESS_INVALID_JSON: ${err.message}`);
  }

  // Structural schema validation
  for (const f of ['protocolVersion', 'asOfDate', 'tenantId', 'bankServicePublicKeyId', 'sealMerkleRoot', 'sealCount', 'seals']) {
    if (witness[f] === undefined || witness[f] === null) {
      throw new Error(`WITNESS_SCHEMA: missing required field '${f}'`);
    }
  }
  if (witness.protocolVersion !== PROTOCOL_VERSION) {
    throw new Error(`WITNESS_SCHEMA: unsupported protocolVersion '${witness.protocolVersion}' (this verifier supports '${PROTOCOL_VERSION}')`);
  }
  if (!Array.isArray(witness.seals) || witness.seals.length === 0) {
    throw new Error('WITNESS_SCHEMA: seals[] must be a non-empty array');
  }
  if (typeof witness.sealCount !== 'number' || !Number.isInteger(witness.sealCount) || witness.sealCount < 1) {
    throw new Error(`WITNESS_SCHEMA: sealCount must be a positive integer, got ${JSON.stringify(witness.sealCount)}`);
  }
  if (witness.seals.length !== witness.sealCount) {
    throw new Error(`WITNESS_SCHEMA: sealCount (${witness.sealCount}) does not match seals.length (${witness.seals.length})`);
  }
  if (witness.sealMerkleRoot !== expectedMerkleRoot) {
    throw new Error(
      `MERKLE_ROOT_MISMATCH: witness claims sealMerkleRoot=${witness.sealMerkleRoot} but XRPL memo anchored ${expectedMerkleRoot}`,
    );
  }

  // Per-seal structural check
  for (let i = 0; i < witness.seals.length; i += 1) {
    const s = witness.seals[i];
    for (const f of ['eventId', 'signedAt', 'canonicalInput', 'signature', 'publicKeyId']) {
      if (typeof s[f] !== 'string' || s[f].length === 0) {
        throw new Error(`WITNESS_SCHEMA: seals[${i}].${f} missing or empty`);
      }
    }
  }

  return witness;
}
