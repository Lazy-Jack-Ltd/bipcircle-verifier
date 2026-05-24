/**
 * keys.js — fetch + parse the bank-service JWKS for a tenant.
 *
 * Endpoint: ${bankServiceUrl}/.well-known/bank-service-keys
 * Response shape per RFC 7517: { keys: [JWK, ...] }
 * Each JWK has kid + kty=EC + crv=P-256 + use=sig + alg=ES256 + x,y.
 *
 * Returns a Map<kid, crypto.KeyObject> ready for ECDSA verification.
 * The verifier matches seal.publicKeyId against kid to select the
 * key for each signature.
 */

'use strict';

import crypto from 'node:crypto';

// Self-audit (v0.1.1): bounded fetch — bank-service /.well-known should
// respond in well under a second; 10s timeout catches a dead endpoint
// without dragging out the verifier.
const DEFAULT_FETCH_TIMEOUT_MS = 10000;

export async function fetchJwks({ bankServiceUrl, fetchImpl = fetch, timeoutMs = DEFAULT_FETCH_TIMEOUT_MS }) {
  if (typeof bankServiceUrl !== 'string' || !bankServiceUrl.startsWith('https://')) {
    throw new Error(`fetchJwks: bankServiceUrl must be https://, got '${bankServiceUrl}'`);
  }
  const url = `${bankServiceUrl.replace(/\/$/, '')}/.well-known/bank-service-keys`;
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) {
    throw new Error(`fetchJwks: HTTP ${res.status} from ${url}`);
  }
  const body = await res.json();
  if (!body || !Array.isArray(body.keys)) {
    throw new Error(`fetchJwks: response from ${url} missing keys[] array`);
  }

  const keysByKid = new Map();
  for (const jwk of body.keys) {
    if (!jwk || typeof jwk.kid !== 'string') continue;
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
      // Algorithm pin: skip anything that isn't EC P-256.
      continue;
    }
    try {
      const keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      keysByKid.set(jwk.kid, keyObject);
    } catch (err) {
      // Malformed JWK — skip with the implicit error path (the seal
      // that references this kid will FAIL verification with a clear
      // "kid not found" message instead).
    }
  }

  if (keysByKid.size === 0) {
    throw new Error(`fetchJwks: ${url} returned zero valid EC P-256 keys`);
  }
  return keysByKid;
}
