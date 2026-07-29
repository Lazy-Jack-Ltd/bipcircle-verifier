/**
 * onchain.js — fetch the on-chain token total supply + compare to
 * the bank-side reserve sum from the witness file.
 *
 * Supports two chains today:
 *   - "ethereum" (ERC-20): JSON-RPC eth_call to the token contract's
 *     totalSupply() function (selector 0x18160ddd). Returns the raw
 *     uint256 in wei-style units; the caller divides by 10^decimals.
 *   - "xrpl" (issued currency): JSON-RPC gateway_balances on the
 *     issuer address; sums outstanding obligations for a currency.
 *
 * Wired into the orchestrator in v0.1.2 (was previously primitives
 * only). The comparison is reserves >= supply (with a configurable
 * tolerance in minor units; default 0).
 */

'use strict';

const ETH_TOTAL_SUPPLY_SELECTOR = '0x18160ddd';
const DEFAULT_FETCH_TIMEOUT_MS = 15000;

/**
 * Ethereum ERC-20 totalSupply via JSON-RPC.
 *
 * @returns {Promise<bigint>}
 */
export async function getEthereumErc20TotalSupply({ rpcUrl, contractAddress, fetchImpl = fetch, timeoutMs = DEFAULT_FETCH_TIMEOUT_MS }) {
  if (typeof rpcUrl !== 'string' || !rpcUrl.startsWith('http')) {
    throw new Error(`getEthereumErc20TotalSupply: rpcUrl required`);
  }
  if (typeof contractAddress !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(contractAddress)) {
    throw new Error(`getEthereumErc20TotalSupply: contractAddress must be 0x + 40 hex chars`);
  }
  const res = await fetchImpl(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'eth_call',
      params: [
        { to: contractAddress, data: ETH_TOTAL_SUPPLY_SELECTOR },
        'latest',
      ],
      id: 1,
    }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`getEthereumErc20TotalSupply: HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`getEthereumErc20TotalSupply: ${body.error.message}`);
  if (!body.result || !/^0x[0-9a-fA-F]+$/.test(body.result)) {
    throw new Error(`getEthereumErc20TotalSupply: unexpected result shape: ${JSON.stringify(body.result)}`);
  }
  return BigInt(body.result);
}

/**
 * XRPL issued-currency obligations.
 *
 * @returns {Promise<string>} decimal string (XRPL amounts preserve precision)
 */
export async function getXrplIssuedSupply({ rpcUrl, issuerAddress, currencyCode, fetchImpl = fetch, timeoutMs = DEFAULT_FETCH_TIMEOUT_MS }) {
  if (typeof rpcUrl !== 'string') throw new Error('getXrplIssuedSupply: rpcUrl required');
  if (typeof issuerAddress !== 'string' || issuerAddress.length === 0) {
    throw new Error('getXrplIssuedSupply: issuerAddress required');
  }
  if (typeof currencyCode !== 'string' || currencyCode.length === 0) {
    throw new Error('getXrplIssuedSupply: currencyCode required');
  }

  const res = await fetchImpl(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      method: 'gateway_balances',
      params: [{ account: issuerAddress, ledger_index: 'validated' }],
    }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`getXrplIssuedSupply: HTTP ${res.status}`);
  const body = await res.json();
  if (!body.result || body.result.status === 'error') {
    throw new Error(`getXrplIssuedSupply: ${body.result?.error_message || 'XRPL RPC error'}`);
  }
  const obligations = body.result.obligations || {};
  const value = obligations[currencyCode] || '0';
  return value;
}

/**
 * Sum the bank-side availableBalance fields from witness seals.
 * Returns a BigInt in MINOR UNITS (pennies / cents) for safe
 * comparison with on-chain supply. Each seal's canonical input is
 * parsed to extract the balance.
 *
 * POR-RESERVE-DOUBLECOUNT-01 (whitehat sweep 3): the naive version summed
 * EVERY balance seal, so N intra-day reads of the same (currency, provider)
 * account were counted N times — a short reserve could show a false PASS — and
 * an unrelated-currency balance (e.g. a USD account in a GBP-token witness) was
 * summed toward this token's backing. This now (a) filters to the token's
 * reserves currency and (b) keeps only the latest balance per (currency,
 * provider) account (by `asOf`, tie broken by the higher eventId) before
 * summing. Defense-in-depth: the producer also dedups at witness-build time, but
 * the verifier must NOT trust that — it re-derives the safe total itself.
 *
 * POR-MULTIBANK-ACCOUNT-01 (2026-07-29): the dedup key was `(currency,
 * provider)`, which collapses SEVERAL ACCOUNTS AT ONE INSTITUTION — the
 * expected shape at ten banks — down to one, under-reporting the reserve and
 * manufacturing a false FAIL. The signed seal payload may now carry an account
 * reference (`bankAccountId`, falling back to `accountId` / `connectionId`);
 * when present it joins the dedup key, so distinct accounts at one provider
 * each contribute their latest balance. Seals without an account reference
 * keep the old `(currency, provider)` collapse — published v1/v2 witnesses
 * verify byte-identically. Mixing referenced and unreferenced seals for the
 * SAME (currency, provider) is rejected loudly: that shape would let the same
 * account be counted twice (once under '' and once under its id), inflating
 * the reserve — the producer must be consistent per provider.
 *
 * @param {Array} witnessSeals — witness.seals[]
 * @param {number} decimals — token decimals (e.g., 2 for GBP-cents)
 * @param {string|null} [reservesCurrency] — only count balances in this fiat
 *   currency (e.g. 'GBP'). When null/empty, no currency filter is applied
 *   (back-compat), but the per-account dedup still runs.
 * @returns {bigint} sum in minor units
 */
export function sumBankReserves(witnessSeals, decimals, reservesCurrency = null, opts = {}) {
  return sumBankReservesDetailed(witnessSeals, decimals, reservesCurrency, opts).totalMinorUnits;
}

/**
 * Detailed variant of sumBankReserves — same gates, same total, plus how many
 * distinct bank accounts and matching balance seals contributed. The caller
 * (index.js) uses the counts to say, per currency cell, whether ANY reserve
 * evidence existed at all — a zero built from zero seals must never be
 * indistinguishable from a genuine zero balance.
 *
 * @returns {{ totalMinorUnits: bigint, accountCount: number, matchedSealCount: number }}
 */
export function sumBankReservesDetailed(witnessSeals, decimals, reservesCurrency = null, opts = {}) {
  if (!Array.isArray(witnessSeals)) {
    throw new Error('sumBankReserves: witnessSeals must be an array');
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) {
    throw new Error(`sumBankReserves: decimals must be 0..18, got ${decimals}`);
  }

  // POR-SEAL-FRESHNESS-01 (2026-07-07): the seal ECDSA signature never expires, so
  // a genuine balance seal from any past instant would otherwise be summable as a
  // CURRENT reserve. Combined with `currentSupply` being read LIVE and `asOfDate`
  // being operator-set/unsigned, that enabled attest-then-drain-then-replay: hold
  // £1m + get a real balance seal, drain to £100k while supply stays 1m tokens,
  // then publish today's witness reusing the OLD seal under asOfDate=today →
  // reserves(1m) >= supply(1m) → false PASS on a real shortfall. Gate every
  // summed seal's signed timestamp to a bounded window around the witness asOfDate
  // (the producer already enforces same-day seals; a stale seal in a witness is an
  // anomaly → fail loud) and require the seal be a genuine balance-endpoint read.
  // `asOfDate` (a UTC date string) + window are passed by the caller; when absent
  // the gate is skipped for back-compat (callers in the real verify flow MUST pass
  // them — see index.js).
  const asOfDate = typeof opts.asOfDate === 'string' ? opts.asOfDate : null;
  const maxSealAgeHours = Number.isFinite(opts.maxSealAgeHours) ? opts.maxSealAgeHours : 48;
  const expectedEndpoint = opts.expectedEndpoint === undefined ? '/v1/balance' : opts.expectedEndpoint;
  const asOfEpochMs = asOfDate ? Date.parse(`${asOfDate}T00:00:00Z`) : NaN;
  if (asOfDate && Number.isNaN(asOfEpochMs)) {
    throw new Error(`sumBankReserves: witness asOfDate is not a valid date: ${asOfDate}`);
  }

  // Collapse to one authoritative balance per account. The account key is
  // (currency, provider, accountRef) — accountRef '' for legacy seals that
  // carry no account identity (POR-MULTIBANK-ACCOUNT-01).
  const latestByAccount = new Map();
  // Guard state per (currency, provider): a provider whose seals MIX
  // account-referenced and unreferenced balances could double-count one
  // account. Fail loud rather than sum ambiguously.
  const groupShape = new Map();
  let matchedSealCount = 0;
  for (const seal of witnessSeals) {
    let payload;
    try {
      const canonicalInput = Buffer.from(seal.canonicalInput, 'base64').toString('utf8');
      payload = JSON.parse(canonicalInput);
    } catch (err) {
      throw new Error(`sumBankReserves: seal ${seal.eventId} canonicalInput is not valid JSON: ${err.message}`);
    }
    const balanceStr = payload.availableBalance;
    if (typeof balanceStr !== 'string') continue; // seal isn't a balance read; skip
    // POR-SEAL-FRESHNESS-01: a balance seal MUST be from the balance endpoint —
    // reject any bank-kid-signed blob of another endpoint/type being summed as a
    // reserve. Enforced only when the caller pins expectedEndpoint (real flow does).
    if (expectedEndpoint && payload.endpoint !== undefined && payload.endpoint !== expectedEndpoint) {
      throw new Error(`sumBankReserves: seal ${seal.eventId} endpoint '${payload.endpoint}' is not the expected balance endpoint '${expectedEndpoint}' — a non-balance seal must not be counted as a reserve (POR-SEAL-FRESHNESS-01)`);
    }
    // POR-SEAL-FRESHNESS-01: gate the seal's signed timestamp to the witness date.
    if (asOfDate) {
      const sealTs = String(payload.asOf || seal.signedAt || '');
      const sealMs = Date.parse(sealTs);
      if (Number.isNaN(sealMs)) {
        throw new Error(`sumBankReserves: seal ${seal.eventId} has no parseable signed timestamp (asOf/signedAt='${sealTs}') — cannot verify freshness (POR-SEAL-FRESHNESS-01)`);
      }
      const ageMs = Math.abs(sealMs - asOfEpochMs);
      if (ageMs > maxSealAgeHours * 3600 * 1000) {
        throw new Error(`sumBankReserves: seal ${seal.eventId} signed ${sealTs} is > ${maxSealAgeHours}h from the witness asOfDate ${asOfDate} — a stale/replayed reserve seal must not back a current supply (POR-SEAL-FRESHNESS-01: attest-then-drain-then-replay)`);
      }
    }
    const currency = typeof payload.currency === 'string' ? payload.currency : '';
    // Only count the token's reserves currency. An empty reservesCurrency means
    // "no config" — fall back to summing all currencies (still deduped).
    if (reservesCurrency && currency !== reservesCurrency) continue;
    const provider = typeof payload.provider === 'string' ? payload.provider : '';
    // POR-MULTIBANK-ACCOUNT-01: account identity, when the producer signed one.
    const accountRefRaw = [payload.bankAccountId, payload.accountId, payload.connectionId]
      .find((v) => typeof v === 'string' && v.length > 0);
    const accountRef = accountRefRaw || '';
    const groupKey = `${currency} ${provider}`;
    const shape = groupShape.get(groupKey) || { withRef: false, withoutRef: false };
    if (accountRef) shape.withRef = true; else shape.withoutRef = true;
    groupShape.set(groupKey, shape);
    if (shape.withRef && shape.withoutRef) {
      throw new Error(
        `sumBankReserves: provider '${provider}' has ${currency} balance seals BOTH with and without an account reference — `
        + `ambiguous account identity could count one account twice, so the sum is refused (POR-MULTIBANK-ACCOUNT-01)`,
      );
    }
    matchedSealCount += 1;
    const key = `${groupKey} ${accountRef}`;
    const asOf = String(payload.asOf || seal.signedAt || '');
    const existing = latestByAccount.get(key);
    const existingAsOf = existing ? existing.asOf : '';
    if (
      !existing
      || asOf > existingAsOf
      || (asOf === existingAsOf && String(seal.eventId) > String(existing.eventId))
    ) {
      latestByAccount.set(key, { balanceStr, asOf, eventId: seal.eventId });
    }
  }

  let total = 0n;
  for (const entry of latestByAccount.values()) {
    total += decimalStringToMinorUnits(entry.balanceStr, decimals);
  }
  return { totalMinorUnits: total, accountCount: latestByAccount.size, matchedSealCount };
}

/**
 * Convert "1234.56" (with arbitrary fractional digits ≤ decimals) to
 * a BigInt in minor units. Rejects negative values + strings with
 * exponents (decimal.js-style strings only).
 */
export function decimalStringToMinorUnits(decimalStr, decimals) {
  if (typeof decimalStr !== 'string' || !/^\d+(\.\d+)?$/.test(decimalStr)) {
    throw new Error(`decimalStringToMinorUnits: bad decimal '${decimalStr}' (expected non-negative plain decimal)`);
  }
  const [whole, frac = ''] = decimalStr.split('.');
  if (frac.length > decimals) {
    throw new Error(`decimalStringToMinorUnits: '${decimalStr}' has ${frac.length} fractional digits, exceeds decimals=${decimals}`);
  }
  const padded = frac.padEnd(decimals, '0');
  return BigInt(whole + padded);
}

/**
 * Compare reserves vs on-chain supply. Returns a structured result.
 *
 * @param {Object} args
 * @param {bigint} args.reservesMinorUnits — sum of witness bank balances
 * @param {bigint} args.onChainSupplyMinorUnits — on-chain totalSupply
 * @param {bigint} [args.toleranceMinorUnits] — allowable shortfall (default 0)
 * @returns {{ ok: boolean, reservesMinorUnits: string, onChainSupplyMinorUnits: string, deltaMinorUnits: string, shortfallMinorUnits: string }}
 */
export function compareReservesVsSupply({ reservesMinorUnits, onChainSupplyMinorUnits, toleranceMinorUnits = 0n }) {
  const delta = reservesMinorUnits - onChainSupplyMinorUnits;
  const shortfall = onChainSupplyMinorUnits - reservesMinorUnits;
  const ok = shortfall <= toleranceMinorUnits;
  return {
    ok,
    reservesMinorUnits: reservesMinorUnits.toString(),
    onChainSupplyMinorUnits: onChainSupplyMinorUnits.toString(),
    deltaMinorUnits: delta.toString(),
    shortfallMinorUnits: shortfall > 0n ? shortfall.toString() : '0',
  };
}
