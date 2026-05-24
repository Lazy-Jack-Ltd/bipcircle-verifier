/**
 * canonical.js — byte-identical canonicalisation to the producer side
 * (BIPCircle's audit.js buildBankServiceSealCanonicalInput, which
 * itself mirrors bank-service's sealSigner.js).
 *
 * THIS FILE IS THE PROTOCOL CONTRACT. If the producer canonicalisation
 * changes, this MUST change in lockstep — verifiers built against an
 * out-of-date canonicalisation will produce false-FAIL verdicts. The
 * shape is pinned by the public-reserve-verifier-protocol.md
 * specification in the BIPCircle repo.
 *
 * Algorithm:
 *   canonicalInput = JSON.stringify(
 *     sortedKeys({ ...payload, tenantId, eventId, signedAt, endpoint })
 *   )
 *
 * - Top-level keys are alphabetically sorted (JS engine-independent).
 * - Nested values are serialised verbatim. Producers MUST construct
 *   payloads with canonical orderings for nested objects; the producer
 *   side (bank-service) builds these from typed route handlers, so
 *   in practice the nested ordering is stable.
 * - Output is a JavaScript string. The signature operates on the
 *   UTF-8 bytes of this string.
 */

'use strict';

export function buildCanonicalInput({ payload, tenantId, eventId, signedAt, endpoint }) {
  if (typeof tenantId !== 'string' || tenantId.length === 0) {
    throw new Error('canonical: tenantId is required');
  }
  if (typeof eventId !== 'string' || eventId.length === 0) {
    throw new Error('canonical: eventId is required');
  }
  if (typeof signedAt !== 'string' || signedAt.length === 0) {
    throw new Error('canonical: signedAt is required');
  }
  if (typeof endpoint !== 'string' || endpoint.length === 0) {
    throw new Error('canonical: endpoint is required (cross-endpoint replay defence)');
  }
  const merged = { ...(payload || {}), tenantId, eventId, signedAt, endpoint };
  const sortedKeys = Object.keys(merged).sort();
  const sorted = {};
  for (const k of sortedKeys) sorted[k] = merged[k];
  return JSON.stringify(sorted);
}
