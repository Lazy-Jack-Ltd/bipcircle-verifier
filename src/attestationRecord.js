/**
 * attestationRecord.js — parse Memo 1 (`treasury-attestation-v1`), the
 * producer's canonical pipe-separated attestation record, and bind it to a
 * currency cell in the pinned registry. (2026-07-29 cell audit, finding 12:
 * the record was extracted by xrpl.js but never consumed, so the verifier's
 * verdict was not bound to the cell the transaction attests.)
 *
 * Record format (eleven positional fields, `|`-separated):
 *
 *   version | asOfDate | chain | tokenKey | currency | verdict
 *           | onChain | ledger | bank | delta | reportId
 *
 * The MemoType is the CHANNEL name and never changes; the LEADING TOKEN is
 * the format version (same discipline as Memo 5's protocolVersion):
 *
 *   v1 (2026-05-23 .. 2026-07-29) — same 11 fields, same order, but two
 *      producer defects (finding 8) meant fields 9 (bank) and 10 (then
 *      specified as deltaBps) were the literal string 'null' in EVERY
 *      record ever anchored under v1. Those transactions are immutable and
 *      MUST remain verifiable: 'null' means "never committed", which is a
 *      DIFFERENT claim from '0' ("committed as zero"). This parser maps the
 *      literal 'null' to JS null and nothing downstream may coerce it to 0.
 *   v2 (2026-07-29 ..) — field 9 carries the actual reserve sum and field
 *      10 the absolute delta in major currency units.
 *
 * TRUST BOUNDARY — what the record is used FOR vs verified AGAINST:
 *
 *   The record is producer-authored. It tells the verifier WHICH cell the
 *   transaction attests (scoping) and WHAT the issuer claimed (surfacing).
 *   The reserve figure still comes ONLY from the signed bank seals and the
 *   supply ONLY from the chain — the claimed onChain/ledger/bank/delta
 *   figures are never inputs to the PASS/FAIL comparison. A published
 *   verdict other than 'balanced' is surfaced (drift → FAIL, coverage →
 *   INCONCLUSIVE) because the issuer's own record disclaims full backing.
 *
 * SUPPORTED_CANONICAL_RECORD_VERSIONS is the fail-closed evolution lever
 * for this record, the exact analogue of witness.js's
 * SUPPORTED_PROTOCOL_VERSIONS: an unknown leading token makes the verdict
 * INCONCLUSIVE ("upgrade the verifier"), never a silent partial read — and
 * never a FAIL, because a newer producer format is evidence the verifier is
 * stale, not that the attestation is fraudulent.
 */

'use strict';

export const SUPPORTED_CANONICAL_RECORD_VERSIONS = new Set(['v1', 'v2']);

/** Verdicts the producer's verdict engine can emit (dailyReserveAttestation.js). */
export const PUBLISHED_VERDICT_BALANCED = 'balanced';
/** Producer DETECTED drift — the record itself is evidence of a discrepancy. */
export const PUBLISHED_DRIFT_VERDICTS = new Set(['out_of_tolerance', 'partial_drift']);
/** Producer could not fully verify (missing view / coverage) — not drift, not clean. */
export const PUBLISHED_COVERAGE_VERDICTS = new Set(['partial_balanced', 'provider_unavailable']);

class RecordError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/**
 * Parse a raw Memo 1 payload into a structured record.
 *
 * @param {string} raw — utf8-decoded MemoData of the
 *   'treasury-attestation-v1' memo
 * @returns {{ version, asOfDate, chain, tokenKey, currency, verdict,
 *             reportId, reportClass: 'combined'|'per-tuple',
 *             claimed: { onChain, ledger, bank, delta } }}
 *   claimed.* are strings in MAJOR currency units as the producer emitted
 *   them, or null when the record carries the literal 'null' (= that view
 *   was never committed — NOT zero).
 * @throws {RecordError} code = 'RECORD_MALFORMED' | 'RECORD_VERSION_UNSUPPORTED'
 */
export function parseCanonicalRecord(raw) {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new RecordError('RECORD_MALFORMED', 'canonical record is empty or not a string');
  }
  const fields = raw.split('|');
  const version = fields[0];
  if (!SUPPORTED_CANONICAL_RECORD_VERSIONS.has(version)) {
    throw new RecordError(
      'RECORD_VERSION_UNSUPPORTED',
      `canonical record version '${String(version).slice(0, 24)}' is not supported by this verifier `
      + `(supported: ${[...SUPPORTED_CANONICAL_RECORD_VERSIONS].join(', ')}). A newer version usually means `
      + `this verifier is out of date — upgrade @lazyjackorg/bipcircle-verifier rather than trusting a partial read.`,
    );
  }
  if (fields.length !== 11) {
    throw new RecordError(
      'RECORD_MALFORMED',
      `canonical record has ${fields.length} fields, expected 11 (${version} format: `
      + `version|asOfDate|chain|tokenKey|currency|verdict|onChain|ledger|bank|delta|reportId)`,
    );
  }
  const [, asOfDate, chain, tokenKey, currency, verdict, onChain, ledger, bank, delta, reportId] = fields;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(asOfDate)) {
    throw new RecordError('RECORD_MALFORMED', `canonical record asOfDate '${asOfDate}' is not a YYYY-MM-DD date`);
  }
  for (const [name, v] of [['chain', chain], ['tokenKey', tokenKey], ['currency', currency], ['verdict', verdict], ['reportId', reportId]]) {
    if (typeof v !== 'string' || v.trim().length === 0) {
      throw new RecordError('RECORD_MALFORMED', `canonical record field '${name}' is empty`);
    }
  }
  // The literal string 'null' means "this view was never committed to the
  // anchored record". It is mapped to JS null and MUST stay null — treating
  // it as 0 would turn "never committed" into "committed as zero", which is
  // a different (and false) claim. Structural in v1 (finding 8); possible
  // per-field in v2 when a view was unreadable on the day.
  const nul = (s) => (s === 'null' ? null : s);
  return {
    version,
    asOfDate,
    chain,
    tokenKey,
    currency,
    verdict,
    reportId,
    // `chain === 'combined'` IS the reportClass marker (2026-07-29 audit,
    // finding 12 correction): one combined row is written per fiat currency,
    // summing that currency's tokens across chains — which is exactly this
    // verifier's cell check, so a combined tx is verified as the whole cell
    // and labelled, never silently treated as a per-tuple attestation.
    reportClass: chain === 'combined' ? 'combined' : 'per-tuple',
    claimed: { onChain: nul(onChain), ledger: nul(ledger), bank: nul(bank), delta: nul(delta) },
  };
}

/**
 * Resolve the fiat currency of the CELL a registry token belongs to.
 *
 * The issuer is a protected cell company: each cell holds exactly one fiat
 * currency and is legally segregated, so the cell currency is the boundary
 * every reserve comparison must respect.
 *
 *   - `reserveCurrency` (explicit, preferred — registry schema v3)
 *   - legacy fallback: for ethereum tokens, `currency` has always been the
 *     fiat denomination (e.g. 'GBP'), so it is a safe cell key
 *   - XRPL tokens' `currency` is the ON-LEDGER TICKER (e.g. 'TVV'), never a
 *     fiat currency — no fallback. Missing reserveCurrency on an XRPL token
 *     resolves to null and the verdict becomes INCONCLUSIVE (fail-closed):
 *     an unassignable token must never silently vanish from the liability.
 *
 * @returns {string|null}
 */
export function resolveCellCurrency(tok) {
  if (typeof tok.reserveCurrency === 'string' && tok.reserveCurrency.trim().length > 0) {
    return tok.reserveCurrency.trim();
  }
  if (tok.chain === 'ethereum' && typeof tok.currency === 'string' && tok.currency.trim().length > 0) {
    return tok.currency.trim();
  }
  return null;
}

/**
 * Bind a parsed record to the currency cell it names, using ONLY the pinned
 * registry as the source of token→cell truth. The record's tokenKey follows
 * the producer's tupleTokenKey derivation:
 *
 *   ethereum → lowercased 0x contract address
 *   xrpl     → `${lowercased fiat currency}.${issuer address}`
 *   combined → `combined:${currency}` with chain === 'combined'
 *
 * The record's own `currency` field is CROSS-CHECKED against the registry's
 * cell resolution: if the producer publishes a token under one currency and
 * the pinned registry places it in another cell, someone is wrong and the
 * result is a loud CELL_BINDING_MISMATCH, never a silent re-scope.
 *
 * @returns {{ ok: true, cellCurrency: string }
 *         | { ok: false, code: string, reason: string }}
 */
export function bindRecordToCell(record, tokens) {
  const list = Array.isArray(tokens) ? tokens : [];

  if (record.reportClass === 'combined') {
    // A combined row names the cell directly — its currency IS the cell.
    return { ok: true, cellCurrency: record.currency };
  }

  if (/^0x[0-9a-fA-F]{40}$/.test(record.tokenKey)) {
    const match = list.find(
      (t) => t.chain === 'ethereum' && typeof t.contract === 'string'
        && t.contract.toLowerCase() === record.tokenKey.toLowerCase(),
    );
    if (!match) {
      return {
        ok: false,
        code: 'TOKEN_NOT_IN_REGISTRY',
        reason: `the transaction's record names ethereum token ${record.tokenKey}, which is not in this verifier's pinned registry — the named cell cannot be verified. Upgrade @lazyjackorg/bipcircle-verifier (or the registry entry is missing this token).`,
      };
    }
    const cell = resolveCellCurrency(match);
    if (!cell) {
      return { ok: false, code: 'CELL_CURRENCY_UNRESOLVED', reason: `registry token '${match.label || match.contract}' matched the record but has no resolvable cell currency` };
    }
    if (cell.toUpperCase() !== record.currency.toUpperCase()) {
      return {
        ok: false,
        code: 'CELL_BINDING_MISMATCH',
        reason: `the anchored record places token ${record.tokenKey} in the ${record.currency} cell but this verifier's pinned registry places it in the ${cell} cell — the producer and the registry disagree about a legally segregated boundary; refusing to verify under either.`,
      };
    }
    return { ok: true, cellCurrency: cell };
  }

  const dot = record.tokenKey.indexOf('.');
  if (dot > 0 && dot < record.tokenKey.length - 1) {
    const fiat = record.tokenKey.slice(0, dot);
    const issuer = record.tokenKey.slice(dot + 1);
    const candidates = list.filter((t) => t.chain === 'xrpl' && t.issuer === issuer);
    if (candidates.length === 0) {
      return {
        ok: false,
        code: 'TOKEN_NOT_IN_REGISTRY',
        reason: `the transaction's record names XRPL issuer ${issuer} (${fiat} cell), which is not in this verifier's pinned registry — the named cell cannot be verified. Upgrade @lazyjackorg/bipcircle-verifier.`,
      };
    }
    const resolved = candidates.map((t) => ({ t, cell: resolveCellCurrency(t) }));
    const match = resolved.find((r) => r.cell && r.cell.toUpperCase() === fiat.toUpperCase());
    if (!match) {
      if (resolved.every((r) => !r.cell)) {
        return { ok: false, code: 'CELL_CURRENCY_UNRESOLVED', reason: `registry token(s) for XRPL issuer ${issuer} matched the record but have no resolvable cell currency` };
      }
      return {
        ok: false,
        code: 'CELL_BINDING_MISMATCH',
        reason: `the anchored record places XRPL issuer ${issuer} in the ${fiat} cell but this verifier's pinned registry places it in ${resolved.filter((r) => r.cell).map((r) => r.cell).join('/')} — the producer and the registry disagree about a legally segregated boundary; refusing to verify under either.`,
      };
    }
    if (match.cell.toUpperCase() !== record.currency.toUpperCase()) {
      return {
        ok: false,
        code: 'CELL_BINDING_MISMATCH',
        reason: `the anchored record's currency field says '${record.currency}' but its tokenKey names the ${match.cell} cell — the record is internally inconsistent; refusing to verify under either.`,
      };
    }
    return { ok: true, cellCurrency: match.cell };
  }

  return {
    ok: false,
    code: 'TOKEN_KEY_UNRECOGNISED',
    reason: `the record's tokenKey '${record.tokenKey}' is neither an ethereum contract address, an XRPL '<currency>.<issuer>' key, nor a combined row — cannot bind the verdict to a cell`,
  };
}
