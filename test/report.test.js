/**
 * report.test.js — the CLI report renderer (v0.3.0): treasury balance is
 * shown formatted (currency + decimals), and the on-ledger links include the
 * XRPL ACCOUNT pages (attestation account + per-XRPL-token issuer), not just
 * the attestation transaction.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { formatMinor, explorerTxUrl, explorerAccountUrl, ethTokenUrl, renderHuman } from '../src/report.js';

describe('formatMinor', () => {
  test('fiat renders with symbol + ≥2dp + thousands separators', () => {
    assert.equal(formatMinor('1000000000000000000', 18, 'GBP'), '£1.00');
    assert.equal(formatMinor('1234560000000000000000', 18, 'GBP'), '£1,234.56');
    assert.equal(formatMinor('0', 18, 'GBP'), '£0.00');
  });
  test('on-ledger ticker (0dp) renders as "N TICKER"', () => {
    assert.equal(formatMinor('5', 0, 'TVV'), '5 TVV');
    assert.equal(formatMinor('12000', 0, 'TVV'), '12,000 TVV');
  });
});

describe('explorer URLs', () => {
  test('account URL is the /accounts/ page (mainnet + testnet)', () => {
    assert.equal(explorerAccountUrl('rIssuer', 'mainnet'), 'https://livenet.xrpl.org/accounts/rIssuer');
    assert.equal(explorerAccountUrl('rIssuer', 'testnet'), 'https://testnet.xrpl.org/accounts/rIssuer');
  });
  test('tx URL is the /transactions/ page', () => {
    assert.equal(explorerTxUrl('ABC', 'testnet'), 'https://testnet.xrpl.org/transactions/ABC');
  });
  test('eth token URL host inferred from label', () => {
    assert.match(ethTokenUrl('0xabc', 'TVV-ETH-Sepolia'), /sepolia\.etherscan\.io\/token\/0xabc/);
    assert.match(ethTokenUrl('0xabc', 'TVV-ETH'), /^https:\/\/etherscan\.io\/token\/0xabc/);
  });
});

describe('renderHuman', () => {
  const result = {
    verdict: 'PASS',
    stages: {
      witness: { asOfDate: '2026-06-15', tenantId: 'tvvin', sealCount: 3 },
      signatures: { sealsVerified: 3, sealsTotal: 3 },
      merkle: { ok: true },
      xrpl: { txHash: 'DEADBEEF', account: 'rat8BjsVkGpWS44tg89QxMmNWjgduw6Ym4' },
      supply: {
        ok: true,
        cellCount: 1,
        tokenCount: 2,
        cells: [{
          currency: 'GBP',
          decimals: 18,
          ok: true,
          reservesMinorUnits: '5000000000000000000',
          onChainSupplyMinorUnits: '5000000000000000000',
          shortfallMinorUnits: '0',
          toleranceMinorUnits: '0',
          reserveAccountCount: 1,
          reserveSealCount: 1,
          perToken: [
            { label: 'TVV-ETH-Sepolia', chain: 'ethereum', currency: 'GBP', cellCurrency: 'GBP', decimals: 18, contract: '0xDc48900756dB73D795cd5C9Fcb6CAABe33De27c4', issuer: null, supplyMinor: '3000000000000000000' },
            { label: 'TVV-XRPL-Testnet', chain: 'xrpl', currency: 'TVV', cellCurrency: 'GBP', decimals: 0, issuer: 'rUQ1ASSoETT3ujFH2N469Nfi1BKW4xDFTf', contract: null, supplyMinor: '2' },
          ],
        }],
      },
    },
    failures: [],
  };

  test('shows the treasury balance formatted (not raw minor units)', () => {
    const out = renderHuman(result, { network: 'testnet' });
    assert.match(out, /bank reserves:\s+£5\.00/);
    assert.match(out, /on-chain supply:\s+£5\.00/);
    assert.match(out, /fully backed/);
    assert.match(out, /\[xrpl\] TVV-XRPL-Testnet: 2 TVV/);
    assert.doesNotMatch(out, /5000000000000000000/); // raw minor units must not leak into the human view
  });

  test('emits the XRPL ACCOUNT links (attestation account + XRPL token issuer), not only the tx', () => {
    const out = renderHuman(result, { network: 'testnet' });
    assert.match(out, /attestation tx:\s+https:\/\/testnet\.xrpl\.org\/transactions\/DEADBEEF/);
    assert.match(out, /attestation account:\s+https:\/\/testnet\.xrpl\.org\/accounts\/rat8BjsVkGpWS44tg89QxMmNWjgduw6Ym4/);
    assert.match(out, /issuer \(balance\):\s+https:\/\/testnet\.xrpl\.org\/accounts\/rUQ1ASSoETT3ujFH2N469Nfi1BKW4xDFTf/);
  });

  test('links the hosted web verifier (shareable treasury URL)', () => {
    const out = renderHuman(result, { network: 'testnet' });
    assert.match(out, /web verifier:\s+https:\/\/lazy-jack-ltd\.github\.io\/bipcircle-verifier\//);
  });

  test('a skipped supply stage renders as NOT VERIFIED with an INCONCLUSIVE verdict block', () => {
    const skipped = {
      verdict: 'INCONCLUSIVE',
      stages: { xrpl: { txHash: 'X', account: 'rA' }, supply: { ok: null, skipped: true, reason: 'skipped by flag (--skip-onchain)' } },
      failures: [],
      inconclusive: [{ stage: 'supply', reason: 'SUPPLY_CHECK_SKIPPED: reserve backing was NOT verified' }],
    };
    const out = renderHuman(skipped, { network: 'testnet' });
    assert.match(out, /VERDICT: INCONCLUSIVE/);
    assert.match(out, /treasury balance: NOT VERIFIED/);
    assert.match(out, /NOT VERIFIED \(verdict cannot be PASS\):/);
    assert.match(out, /SUPPLY_CHECK_SKIPPED/);
    assert.match(out, /attestation account:\s+https:\/\/testnet\.xrpl\.org\/accounts\/rA/); // account link still shown
  });

  test('per-cell figures are NEVER totalled across cells (no cross-currency sum line)', () => {
    const twoCells = {
      verdict: 'FAIL',
      stages: {
        xrpl: { txHash: 'X', account: 'rA' },
        supply: {
          ok: false,
          cellCount: 2,
          tokenCount: 2,
          cells: [
            { currency: 'EUR', decimals: 2, ok: true, reservesMinorUnits: '1000000000', onChainSupplyMinorUnits: '10000', shortfallMinorUnits: '0', toleranceMinorUnits: '0', reserveAccountCount: 1, perToken: [] },
            { currency: 'GBP', decimals: 2, ok: false, reservesMinorUnits: '50000000', onChainSupplyMinorUnits: '100000000', shortfallMinorUnits: '50000000', toleranceMinorUnits: '0', reserveAccountCount: 1, perToken: [] },
          ],
        },
      },
      failures: [{ stage: 'supply', reason: 'RESERVE_SHORTFALL[GBP]: …' }],
      inconclusive: [],
    };
    const out = renderHuman(twoCells, { network: 'testnet' });
    assert.match(out, /\[EUR\] cell:/);
    assert.match(out, /\[GBP\] cell:/);
    assert.match(out, /✗ SHORTFALL £500,000\.00/);
    assert.match(out, /✓ fully backed/);
    // €10m + £500k must never appear as one merged figure under one symbol.
    assert.doesNotMatch(out, /£10,500,000/);
    assert.doesNotMatch(out, /€10,500,000/);
  });
});
