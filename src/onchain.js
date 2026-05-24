/**
 * onchain.js — fetch the on-chain token total supply for the tenant's
 * stablecoin.
 *
 * Supports two chains today:
 *   - "ethereum" (ERC-20): JSON-RPC eth_call to the token contract's
 *     totalSupply() function (selector 0x18160ddd). Returns the raw
 *     uint256 in wei-style units; the caller divides by 10^decimals.
 *   - "xrpl" (issued currency): JSON-RPC account_lines on the issuer
 *     address to sum outstanding obligations for a currency code.
 *
 * The supply is compared against the sum of bank-side availableBalance
 * fields in the witness. PASS = reserves >= supply (within optional
 * tolerance). Currency / decimal alignment is the caller's job —
 * the witness payload + the on-chain contract metadata together
 * specify the units.
 */

'use strict';

const ETH_TOTAL_SUPPLY_SELECTOR = '0x18160ddd';

/**
 * Ethereum ERC-20 totalSupply via JSON-RPC.
 *
 * @returns {Promise<bigint>}
 */
export async function getEthereumErc20TotalSupply({ rpcUrl, contractAddress, fetchImpl = fetch }) {
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
 * XRPL issued-currency obligations (= total supply minus issuer's
 * own balance, in XRPL accounting).
 *
 * Returns the sum of outstanding obligations as a decimal string
 * (XRPL amounts are stored as strings to preserve precision).
 *
 * @returns {Promise<string>}
 */
export async function getXrplIssuedSupply({ rpcUrl, issuerAddress, currencyCode, fetchImpl = fetch }) {
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
  });
  if (!res.ok) throw new Error(`getXrplIssuedSupply: HTTP ${res.status}`);
  const body = await res.json();
  if (!body.result || body.result.status === 'error') {
    throw new Error(`getXrplIssuedSupply: ${body.result?.error_message || 'XRPL RPC error'}`);
  }
  // gateway_balances returns obligations grouped by currency code.
  const obligations = body.result.obligations || {};
  const value = obligations[currencyCode] || '0';
  return value;
}
