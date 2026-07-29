/**
 * report.js — human-readable rendering of a verify() result + the block-
 * explorer URL builders. Pure functions (no I/O) so the output is unit-
 * testable and reusable by the CLI.
 *
 * v0.3.0 — surfaces the TREASURY BALANCE (formatted, with currency) and
 * clickable XRPL ACCOUNT links (not just the attestation transaction), so a
 * reviewer can click straight through to the issuer account whose on-ledger
 * obligations ARE the issued balance. Previously the CLI emitted only a link
 * to the attestation tx and the reserve/supply figures in raw minor units.
 */

// Hosted browser verifier (GitHub Pages) — reads the live on-chain treasury balance + links to the
// XRP Ledger. Shareable URL for a regulator/holder who doesn't want to run the CLI.
export const WEB_VERIFIER_URL = 'https://lazy-jack-ltd.github.io/bipcircle-verifier/';

// Official XRPL Foundation explorers (no third-party trust required).
const XRPL_HOST = { mainnet: 'livenet.xrpl.org', testnet: 'testnet.xrpl.org' };
const CURRENCY_SYMBOL = { GBP: '£', USD: '$', EUR: '€', JPY: '¥' };

export function explorerTxUrl(txHash, network = 'mainnet') {
  return `https://${XRPL_HOST[network] || XRPL_HOST.mainnet}/transactions/${txHash}`;
}

export function explorerAccountUrl(address, network = 'mainnet') {
  return `https://${XRPL_HOST[network] || XRPL_HOST.mainnet}/accounts/${address}`;
}

/** Best-effort Etherscan token link (host inferred from the token label, e.g. "…-Sepolia"). */
export function ethTokenUrl(contract, label = '') {
  const host = /sepolia/i.test(label) ? 'sepolia.etherscan.io' : 'etherscan.io';
  return `https://${host}/token/${contract}`;
}

/**
 * Format a minor-units integer (string/bigint) to a human balance with the
 * token's decimals + currency. Fiat currencies render with their symbol and
 * at least 2 dp (e.g. "£1,000.00"); on-ledger tickers render as "5 TVV".
 */
export function formatMinor(minorStr, decimals = 0, currency = '') {
  let s = String(minorStr ?? '0');
  const neg = s.startsWith('-');
  if (neg) s = s.slice(1);
  if (!/^\d+$/.test(s)) return `${minorStr}${currency ? ` ${currency}` : ''}`; // non-integer: show as-is
  const d = Number(decimals) || 0;
  let whole;
  let frac;
  if (d === 0) { whole = s; frac = ''; } else {
    s = s.padStart(d + 1, '0');
    whole = s.slice(0, -d);
    frac = s.slice(-d).replace(/0+$/, '');
  }
  whole = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ','); // thousands separators
  const sym = CURRENCY_SYMBOL[currency];
  if (sym) frac = (frac || '').padEnd(2, '0'); // fiat: always ≥ 2dp
  const num = frac ? `${whole}.${frac}` : whole;
  const body = sym ? `${sym}${num}` : (currency ? `${num} ${currency}` : num);
  return neg ? `-${body}` : body;
}

/** Render a verify() result as the CLI's human-readable report. */
export function renderHuman(result, { network = 'mainnet', txHash } = {}) {
  const L = [''];
  L.push(`VERDICT: ${result.verdict}`);

  const w = result.stages?.witness;
  if (w) {
    L.push(`  asOfDate: ${w.asOfDate}`);
    L.push(`  tenantId: ${w.tenantId}`);
    L.push(`  sealCount: ${w.sealCount}`);
  }
  const sig = result.stages?.signatures;
  if (sig) L.push(`  signatures: ${sig.sealsVerified}/${sig.sealsTotal} OK`);
  const mk = result.stages?.merkle;
  if (mk) L.push(`  merkle root: ${mk.ok ? 'OK' : 'MISMATCH'}`);

  const s = result.stages?.supply;
  if (s && !s.skipped && Array.isArray(s.cells)) {
    // v0.5.0 — per-currency-cell verification. Each cell is legally
    // segregated, so figures are NEVER totalled across cells: a cross-cell
    // total is exactly the netting this verifier exists to refuse.
    L.push('');
    L.push(`  TREASURY — bank reserves vs on-chain supply, per currency cell (${s.cellCount} cell${s.cellCount === 1 ? '' : 's'}, ${s.tokenCount} token${s.tokenCount === 1 ? '' : 's'}):`);
    for (const c of s.cells) {
      const dec = c.decimals ?? 0;
      const cur = c.currency || '';
      const accounts = c.reserveAccountCount ?? 0;
      L.push(`    [${cur}] cell:`);
      L.push(`      bank reserves:    ${formatMinor(c.reservesMinorUnits, dec, cur)}  (${accounts} bank account${accounts === 1 ? '' : 's'})`);
      L.push(`      on-chain supply:  ${formatMinor(c.onChainSupplyMinorUnits, dec, cur)}`);
      L.push(`      result:           ${c.ok ? '✓ fully backed (reserves ≥ supply)' : `✗ SHORTFALL ${formatMinor(c.shortfallMinorUnits, dec, cur)}`}`);
      for (const t of (c.perToken || [])) {
        L.push(`        └ [${t.chain}] ${t.label}: ${formatMinor(t.supplyMinor, t.decimals ?? 0, t.currency || '')}`);
      }
    }
  } else if (s?.skipped) {
    L.push(`  treasury balance: NOT VERIFIED (${s.reason || 'on-chain supply check skipped'})`);
  }

  if (result.failures?.length) {
    L.push('');
    L.push('FAILURES:');
    for (const f of result.failures) L.push(`  [${f.stage}] ${f.reason}`);
  }
  if (result.inconclusive?.length) {
    L.push('');
    L.push('NOT VERIFIED (verdict cannot be PASS):');
    for (const f of result.inconclusive) L.push(`  [${f.stage}] ${f.reason}`);
  }

  // On-ledger links — always the attestation tx + account; per-token issuer/contract when known.
  const tx = txHash || result.stages?.xrpl?.txHash;
  const acct = result.stages?.xrpl?.account;
  L.push('');
  L.push('VIEW ON-LEDGER:');
  if (tx) L.push(`  attestation tx:        ${explorerTxUrl(tx, network)}`);
  if (acct) L.push(`  attestation account:   ${explorerAccountUrl(acct, network)}`);
  const linkTokens = (result.stages?.supply?.cells || []).flatMap((c) => c.perToken || []);
  for (const t of linkTokens) {
    if (t.chain === 'xrpl' && t.issuer) {
      L.push(`  ${t.label} issuer (balance): ${explorerAccountUrl(t.issuer, network)}`);
    } else if (t.chain === 'ethereum' && t.contract) {
      L.push(`  ${t.label} token:        ${ethTokenUrl(t.contract, t.label)}`);
    }
  }
  L.push(`  web verifier:          ${WEB_VERIFIER_URL}`);

  return `${L.join('\n')}\n`;
}
