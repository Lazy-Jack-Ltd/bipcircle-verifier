/**
 * tenantRegistry.js — pinned per-tenant trust roots.
 *
 * Each tenant entry binds the verifier to:
 *   - tenantId: the PIN NAME — the value passed to `--tenant`. This is
 *     this verifier's public CLI surface, NOT necessarily what BIPCircle
 *     calls the deployment.
 *   - bipcircleTenantId: the BIPCircle platform tenant id. Load-bearing:
 *     the witness file's `tenantId` must equal it, which is what keeps
 *     two deployments that share a bank-service URL and signing key from
 *     being interchangeable. Falls back to tenantId when absent.
 *   - bankServiceUrl: the canonical bank-service base URL (HTTPS)
 *   - xrplPublishingAccount: the XRPL account the daily attestation tx
 *     MUST be signed by and sent from (defends Pro F2). This is the
 *     producer's per-tenant anchor wallet. It is NOT a token issuer and
 *     NOT an EVM contract — see THREE_SEPARATE_IDENTITIES in tenants.json.
 *     Accepts the deprecated name `xrplIssuerAddress` as an alias, because
 *     silently dropping the F2 gate on an older third-party entry would be
 *     worse than carrying the alias; an entry setting BOTH to different
 *     values is rejected at load rather than guessed.
 *   - bankServices[] (schema v5): { url, kidPattern } per bank service.
 *     The v4 single `bankServiceUrl` + `kidPattern` is read as a
 *     one-element list (see normaliseBankServices).
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

/**
 * Normalise one raw registry entry into the internal shape.
 *
 * ONE implementation, shared by the real loader and the test helper. They
 * used to carry separate copies of this logic, which meant a test fixture
 * could be accepted in a shape the shipped loader would reject (or vice
 * versa) and no test could see the difference.
 *
 * Resolves:
 *   - tokens[] from the legacy single `token` object
 *   - the kid pattern regex
 *   - xrplPublishingAccount from its deprecated alias xrplIssuerAddress
 *   - bipcircleTenantId, defaulting to the pin name
 */
function normaliseTenant(t) {
  const normalisedTokens = Array.isArray(t.tokens)
    ? t.tokens
    : (t.token ? [t.token] : []);

  // Deprecated alias. An entry may use either name, but if it sets both to
  // DIFFERENT accounts the two disagree about the F2 trust root and there
  // is no safe way to pick one — refuse to load rather than guess.
  const pub = t.xrplPublishingAccount;
  const alias = t.xrplIssuerAddress;
  if (pub && alias && pub !== alias) {
    throw new Error(
      `tenantRegistry: tenant '${t.tenantId}' sets xrplPublishingAccount='${pub}' AND the deprecated `
      + `alias xrplIssuerAddress='${alias}' to different values. These name the SAME trust root (the `
      + `account the attestation tx must be signed by); a disagreement cannot be resolved safely. `
      + `Remove xrplIssuerAddress — and note it never meant the token issuer, which lives on tokens[].issuer.`,
    );
  }

  return {
    ...t,
    bankServices: normaliseBankServices(t),
    tokens: normalisedTokens,
    xrplPublishingAccount: pub || alias || null,
    bipcircleTenantId: t.bipcircleTenantId || t.tenantId,
  };
}

/**
 * Resolve an entry's bank services (schema v5, multi-bank).
 *
 * A reserve can sit at several banks, each read through its OWN bank-service
 * deployment with its OWN signing key. `bankServices[]` lists them, each with
 * a `url` and a `kidPattern`; a seal is verified against the bank service
 * whose kidPattern matches the kid it carries, never against a pooled key set.
 *
 * The v4 single-service shape (`bankServiceUrl` + `kidPattern` at the top of
 * the entry) is still read, as a one-element list. An entry that sets BOTH
 * shapes must repeat the legacy pair verbatim inside `bankServices[]`; any
 * other combination names two trust roots for one slot and is refused at load
 * rather than guessed (the same rule as xrplIssuerAddress).
 *
 * With more than one service every entry must carry a kidPattern: without it
 * there is no way to say which bank service a seal belongs to.
 */
function normaliseBankServices(t) {
  const legacy = t.bankServiceUrl
    ? { url: t.bankServiceUrl, kidPattern: t.kidPattern ?? null }
    : null;
  if (!legacy && t.kidPattern && !Array.isArray(t.bankServices)) {
    throw new Error(`tenantRegistry: tenant '${t.tenantId}' sets kidPattern with no bankServiceUrl; a key pattern needs the bank service it belongs to.`);
  }
  let list;
  if (Array.isArray(t.bankServices)) {
    if (t.bankServices.length === 0) {
      throw new Error(`tenantRegistry: tenant '${t.tenantId}' has an empty bankServices[]; list at least one bank service or remove the field.`);
    }
    list = t.bankServices.map((s, i) => {
      if (!s || typeof s.url !== 'string' || s.url.length === 0) {
        throw new Error(`tenantRegistry: tenant '${t.tenantId}' bankServices[${i}] has no url.`);
      }
      return { url: s.url, kidPattern: s.kidPattern ?? null, label: s.label ?? null };
    });
    if (legacy && !list.some((s) => s.url === legacy.url && s.kidPattern === legacy.kidPattern)) {
      throw new Error(
        `tenantRegistry: tenant '${t.tenantId}' sets the single-service bankServiceUrl/kidPattern AND bankServices[], `
        + `and the single pair ('${legacy.url}', '${legacy.kidPattern}') is not one of the listed services. `
        + `The two shapes disagree about a trust root; remove bankServiceUrl/kidPattern or make them match an entry.`,
      );
    }
  } else {
    list = legacy ? [legacy] : [];
  }
  const urls = new Set();
  for (const s of list) {
    if (urls.has(s.url)) {
      throw new Error(`tenantRegistry: tenant '${t.tenantId}' lists bank service '${s.url}' twice.`);
    }
    urls.add(s.url);
    if (list.length > 1 && !s.kidPattern) {
      throw new Error(
        `tenantRegistry: tenant '${t.tenantId}' lists ${list.length} bank services but '${s.url}' has no kidPattern, `
        + `so a seal could not be attributed to one of them.`,
      );
    }
  }
  return list.map((s) => ({ ...s, _kidRegex: s.kidPattern ? new RegExp(s.kidPattern) : null }));
}

/**
 * The bank service a kid belongs to: the ONE service whose kidPattern matches
 * it. A lone service without a pattern (unsafe-override mode) takes every kid.
 *
 * @returns {{ service: object|null, reason: 'ok'|'not-pinned'|'ambiguous' }}
 */
export function resolveBankServiceForKid(bankServices, kid) {
  if (bankServices.length === 1 && !bankServices[0]._kidRegex) {
    return { service: bankServices[0], reason: 'ok' };
  }
  const matches = bankServices.filter((s) => s._kidRegex && typeof kid === 'string' && s._kidRegex.test(kid));
  if (matches.length === 1) return { service: matches[0], reason: 'ok' };
  return { service: null, reason: matches.length === 0 ? 'not-pinned' : 'ambiguous' };
}

function buildRegistry(parsed, source) {
  if (!parsed || !Array.isArray(parsed.tenants)) {
    throw new Error(`tenantRegistry: malformed registry from ${source} — missing tenants[] array`);
  }
  const tenants = parsed.tenants.map(normaliseTenant);
  return { tenants, byId: new Map(tenants.map((t) => [t.tenantId, t])) };
}

export function loadTenantRegistry() {
  if (cached) return cached;
  const raw = readFileSync(REGISTRY_PATH, 'utf8');
  cached = buildRegistry(JSON.parse(raw), REGISTRY_PATH);
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
  // Goes through the SAME normaliser as the shipped loader — see
  // normaliseTenant. A test fixture that the real registry would reject
  // must fail here too.
  cached = buildRegistry(payload, '_setForTests');
}
