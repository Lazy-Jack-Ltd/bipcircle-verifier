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
 * @param {Array} witnessSeals — witness.seals[]
 * @param {number} decimals — token decimals (e.g., 2 for GBP-cents)
 * @param {string|null} [reservesCurrency] — only count balances in this fiat
 *   currency (e.g. 'GBP'). When null/empty, no currency filter is applied
 *   (back-compat), but the per-account dedup still runs.
 * @returns {bigint} sum in minor units
 */
export function sumBankReserves(witnessSeals, decimals, reservesCurrency = null) {
  if (!Array.isArray(witnessSeals)) {
    throw new Error('sumBankReserves: witnessSeals must be an array');
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) {
    throw new Error(`sumBankReserves: decimals must be 0..18, got ${decimals}`);
  }

  // Collapse to one authoritative balance per (currency, provider) account.
  const latestByAccount = new Map();
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
    const currency = typeof payload.currency === 'string' ? payload.currency : '';
    // Only count the token's reserves currency. An empty reservesCurrency means
    // "no config" — fall back to summing all currencies (still deduped).
    if (reservesCurrency && currency !== reservesCurrency) continue;
    const provider = typeof payload.provider === 'string' ? payload.provider : '';
    const key = `${currency} ${provider}`;
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
  return total;
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
