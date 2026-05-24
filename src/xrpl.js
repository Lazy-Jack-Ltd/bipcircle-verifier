/**
 * xrpl.js — fetch + parse a treasury attestation transaction from
 * the XRPL via public JSON-RPC. No SDK dependency — uses native fetch
 * + the standard `tx` command.
 *
 * MemoType / MemoData fields come back as uppercase hex. We decode
 * Memo 5 (`reserve-verifier-v1`) and Memo 1 (`treasury-attestation-v1`)
 * for the verifier's needs.
 */

'use strict';

const DEFAULT_RPC_URLS = {
  mainnet: 'https://s1.ripple.com:51234/',
  testnet: 'https://s.altnet.rippletest.net:51234/',
};

// Self-audit (v0.1.1): every external fetch needs a timeout. A slow or
// hung RPC endpoint must not block the verifier indefinitely. 15s is
// generous for a single XRPL tx lookup; --rpc-timeout flag can override.
const DEFAULT_FETCH_TIMEOUT_MS = 15000;

const MEMO_TYPE_VERIFIER = 'reserve-verifier-v1';
const MEMO_TYPE_CANONICAL = 'treasury-attestation-v1';

function hexToUtf8(hex) {
  return Buffer.from(hex, 'hex').toString('utf8');
}

/**
 * Fetches a transaction and extracts the verifier-protocol memo.
 *
 * @param {Object} args
 * @param {string} args.txHash      — XRPL transaction hash (64 hex chars)
 * @param {string} [args.network]   — "mainnet" | "testnet" (default mainnet)
 * @param {string} [args.rpcUrl]    — override RPC URL
 * @param {Function} [args.fetchImpl] — injection for tests
 * @returns {Promise<{ verifierMemo: Object, canonicalRecord: string,
 *                     ledgerIndex: number, account: string }>}
 */
export async function fetchAttestationTx({ txHash, network = 'mainnet', rpcUrl, fetchImpl = fetch, timeoutMs = DEFAULT_FETCH_TIMEOUT_MS }) {
  if (typeof txHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(txHash)) {
    throw new Error(`fetchAttestationTx: txHash must be 64 hex chars, got '${txHash}'`);
  }
  const url = rpcUrl || DEFAULT_RPC_URLS[network];
  if (!url) {
    throw new Error(`fetchAttestationTx: unknown network '${network}' — pass --rpc-url explicitly`);
  }
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      method: 'tx',
      params: [{ transaction: txHash, binary: false }],
    }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) {
    throw new Error(`fetchAttestationTx: XRPL RPC HTTP ${res.status} from ${url}`);
  }
  const body = await res.json();
  if (!body.result || body.result.status === 'error') {
    throw new Error(`fetchAttestationTx: XRPL RPC error: ${body.result?.error_message || body.result?.error || 'unknown'}`);
  }
  const memos = (body.result.Memos || []).map((m) => ({
    type: m.Memo?.MemoType ? hexToUtf8(m.Memo.MemoType) : '',
    data: m.Memo?.MemoData ? hexToUtf8(m.Memo.MemoData) : '',
  }));
  const verifierMemoStr = memos.find((m) => m.type === MEMO_TYPE_VERIFIER)?.data;
  if (!verifierMemoStr) {
    throw new Error(`fetchAttestationTx: tx ${txHash} has no '${MEMO_TYPE_VERIFIER}' memo — not a v2 reserve attestation`);
  }
  let verifierMemo;
  try {
    verifierMemo = JSON.parse(verifierMemoStr);
  } catch (err) {
    throw new Error(`fetchAttestationTx: '${MEMO_TYPE_VERIFIER}' memo is not valid JSON: ${err.message}`);
  }
  const canonicalRecord = memos.find((m) => m.type === MEMO_TYPE_CANONICAL)?.data || null;
  return {
    verifierMemo,
    canonicalRecord,
    ledgerIndex: body.result.ledger_index,
    account: body.result.Account,
  };
}
