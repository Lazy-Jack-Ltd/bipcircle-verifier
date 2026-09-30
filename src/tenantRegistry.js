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
 *   - bankServices[]: each bank-service deployment the tenant's seals may
 *     come from, as { label, bankServiceUrl (HTTPS), kidPattern } (v0.7.1;
 *     the older single bankServiceUrl + kidPattern is read as one entry).
 *     A transaction is checked against the one whose kidPattern matches.
 *   - xrplPublishingAccount: the XRPL account the daily attestation tx
 *     MUST be signed by and sent from (defends Pro F2). This is the
 *     producer's per-tenant anchor wallet. It is NOT a token issuer and
 *     NOT an EVM contract — see THREE_SEPARATE_IDENTITIES in tenants.json.
 *     Accepts the deprecated name `xrplIssuerAddress` as an alias, because
 *     silently dropping the F2 gate on an older third-party entry would be
 *     worse than carrying the alias; an entry setting BOTH to different
 *     values is rejected at load rather than guessed.
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
/**
 * v0.7.1 — the bank-service deployments a tenant's seals may come from.
 *
 * A tenant can move to a new bank-service deployment with its own signing
 * key (tvvin-sandbox did on 2026-09-27). The new deployment's JWKS lists
 * only the new key, so replacing the pin would make every attestation
 * published before the move unverifiable. Instead the entry lists each
 * deployment with its own kid pattern, and a transaction is checked against
 * the ONE deployment whose pattern its signing key id matches.
 *
 * Accepts the legacy single `bankServiceUrl` + `kidPattern` as a one-entry
 * list. An entry setting both forms is refused rather than merged. With
 * more than one deployment every entry must carry a kid pattern, because
 * the pattern is what selects the deployment.
 */
function normaliseBankServices(t) {
  const hasList = t.bankServices !== undefined;
  if (hasList && (t.bankServiceUrl !== undefined || t.kidPattern !== undefined)) {
    throw new Error(
      `tenantRegistry: tenant '${t.tenantId}' sets bankServices AND the single bankServiceUrl/kidPattern. `
      + `Use one form; list every deployment under bankServices.`,
    );
  }
  const raw = hasList ? t.bankServices : [{ bankServiceUrl: t.bankServiceUrl, kidPattern: t.kidPattern }];
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error(`tenantRegistry: tenant '${t.tenantId}' bankServices must be a non-empty array`);
  }
  const seen = new Set();
  return raw.map((s, i) => {
    const where = `tenant '${t.tenantId}' bankServices[${i}]`;
    if (!s || typeof s.bankServiceUrl !== 'string' || !s.bankServiceUrl.startsWith('https://')) {
      throw new Error(`tenantRegistry: ${where} needs an https:// bankServiceUrl`);
    }
    if (seen.has(s.bankServiceUrl)) {
      throw new Error(`tenantRegistry: ${where} repeats bankServiceUrl '${s.bankServiceUrl}'`);
    }
    seen.add(s.bankServiceUrl);
    if (raw.length > 1 && (typeof s.kidPattern !== 'string' || s.kidPattern.length === 0)) {
      throw new Error(`tenantRegistry: ${where} needs a kidPattern: with several deployments the pattern selects one`);
    }
    return Object.freeze({
      label: s.label || s.bankServiceUrl,
      bankServiceUrl: s.bankServiceUrl,
      kidRegex: s.kidPattern ? new RegExp(s.kidPattern) : null,
    });
  });
}

/**
 * The deployment a signing key id belongs to. Exactly one must match: none
 * means the key is not pinned for this tenant, and more than one means the
 * registry's patterns overlap, which is a registry defect, never a guess.
 */
export function selectBankService(bankServices, kid) {
  if (bankServices.length === 1 && !bankServices[0].kidRegex) return { service: bankServices[0] };
  const matches = bankServices.filter((s) => s.kidRegex && s.kidRegex.test(kid));
  if (matches.length === 1) return { service: matches[0] };
  return { service: null, matchCount: matches.length };
}

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
