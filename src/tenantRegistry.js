/**
 * tenantRegistry.js — pinned per-tenant trust roots.
 *
 * Each tenant entry binds the verifier to:
 *   - bankServiceUrl: the canonical bank-service base URL (HTTPS)
 *   - xrplIssuerAddress: the XRPL account address the daily
 *     attestation tx MUST come from (defends Pro F2)
 *   - kidPattern: a regex matching the expected KMS
 *     CryptoKeyVersion resource name pattern for this tenant's
 *     bank-service signing key (defends Pro F1 by binding the JWKS
 *     identity to operator-supplied source rather than user-supplied
 *     URL)
 *   - token: { chain, contract|issuer, currency, decimals } — for
 *     the on-chain supply comparison (forward-port from 0.2.0)
 *
 * Updates: a new tenant onboarding to v2 seals flips on via an
 * operator PR to src/tenants.json, followed by a new verifier
 * release. Verifiers in the field upgrade when the next tenant
 * comes online OR they pass `--unsafe-tenant-override` for ad-hoc
 * verification of unregistered tenants (operator-explicit risk).
 */

'use strict';

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const REGISTRY_PATH = resolve(here, 'tenants.json');

let cached = null;

export function loadTenantRegistry() {
  if (cached) return cached;
  const raw = readFileSync(REGISTRY_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed || !Array.isArray(parsed.tenants)) {
    throw new Error(`tenantRegistry: malformed tenants.json at ${REGISTRY_PATH} — missing tenants[] array`);
  }
  // Build kid pattern regexes once.
  const tenants = parsed.tenants.map((t) => ({
    ...t,
    _kidRegex: t.kidPattern ? new RegExp(t.kidPattern) : null,
  }));
  cached = { tenants, byId: new Map(tenants.map((t) => [t.tenantId, t])) };
  return cached;
}

export function lookupTenant(tenantId) {
  const reg = loadTenantRegistry();
  return reg.byId.get(tenantId) || null;
}

export function listTenantIds() {
  return loadTenantRegistry().tenants.map((t) => t.tenantId);
}

/**
 * Test-only — reset the cache so a test can swap in a different
 * registry payload without restart.
 */
export function _resetForTests() {
  cached = null;
}

/**
 * Test-only — install a synthetic registry for a single test.
 */
export function _setForTests(payload) {
  if (!payload || !Array.isArray(payload.tenants)) {
    throw new Error('_setForTests: payload must have tenants[]');
  }
  const tenants = payload.tenants.map((t) => ({
    ...t,
    _kidRegex: t.kidPattern ? new RegExp(t.kidPattern) : null,
  }));
  cached = { tenants, byId: new Map(tenants.map((t) => [t.tenantId, t])) };
}
