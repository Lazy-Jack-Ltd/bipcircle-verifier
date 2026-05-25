#!/usr/bin/env node
/**
 * bipcircle-verify — open-source CLI for the BIPCircle public-reserve-
 * verifier protocol v1.
 *
 * Two modes:
 *
 *   PINNED (preferred):
 *     bipcircle-verify --xrpl-tx <hash> --tenant <tenantId>
 *
 *     Trust roots come from this verifier's pinned src/tenants.json.
 *     Closes Pro audit F1+F2 (user-supplied URL / TX-from-any-account
 *     spoofing). On-chain supply comparison wired in via tenant
 *     registry's token config — output reports
 *     "reserves = X, supply = Y, match ✓" or "shortfall of Z".
 *
 *   UNSAFE-OVERRIDE:
 *     bipcircle-verify --xrpl-tx <hash> \
 *         --unsafe-bank-service-url <url> --unsafe-issuer <address>
 *
 *     For ad-hoc verification of tenants not yet in the pinned
 *     registry. Operator accepts the trust-anchor responsibility.
 */

'use strict';

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { platform } from 'node:os';
import { verify } from '../src/index.js';
import { listTenantIds } from '../src/tenantRegistry.js';

function explorerUrl(txHash, network) {
  // Official XRPL Foundation explorers — sibling subdomains, same UI.
  // testnet.xrpl.org is the canonical test-network explorer; livenet.xrpl.org
  // is the mainnet one. No third-party trust required.
  const host = network === 'testnet' ? 'testnet.xrpl.org' : 'livenet.xrpl.org';
  return `https://${host}/transactions/${txHash}`;
}

function openInBrowser(url) {
  const p = platform();
  const cmd = p === 'darwin' ? 'open' : p === 'win32' ? 'start' : 'xdg-open';
  try {
    spawn(cmd, [url], { detached: true, stdio: 'ignore' }).unref();
    return true;
  } catch {
    return false;
  }
}

async function promptOpen(url) {
  // No-op in non-TTY contexts (CI, pipes) — print URL and return.
  if (!process.stdin.isTTY || !process.stdout.isTTY) return;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  await new Promise((resolve) => {
    rl.question('Press Enter to open in browser (or Ctrl+C to skip)... ', () => {
      rl.close();
      openInBrowser(url);
      resolve();
    });
  });
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { args.help = true; continue; }
    if (a === '--json') { args.json = true; continue; }
    if (a === '--skip-onchain') { args['skip-onchain'] = true; continue; }
    if (a.startsWith('--')) {
      const body = a.slice(2);
      const eqIdx = body.indexOf('=');
      if (eqIdx >= 0) {
        args[body.slice(0, eqIdx)] = body.slice(eqIdx + 1);
      } else {
        args[body] = argv[i + 1];
        i += 1;
      }
    }
  }
  return args;
}

function printHelp() {
  let registeredIds = [];
  try { registeredIds = listTenantIds(); } catch (e) { /* registry missing — handled in verify */ }
  process.stdout.write(`bipcircle-verify — public-reserve-verifier protocol v1

USAGE (pinned tenant, preferred):
  bipcircle-verify --xrpl-tx <hash> --tenant <tenantId>

USAGE (unsafe override, ad-hoc):
  bipcircle-verify --xrpl-tx <hash> \\
      --unsafe-bank-service-url <url> --unsafe-issuer <xrpl-address>

PINNED TENANTS in this build:
  ${registeredIds.length > 0 ? registeredIds.join(', ') : '(none — registry empty; use unsafe-override mode)'}

OPTIONS:
  --network <name>          "mainnet" (default) | "testnet"
  --rpc-url <url>            Override XRPL JSON-RPC endpoint
  --eth-rpc-url <url>        Ethereum JSON-RPC for the on-chain supply
                             stage (required when the tenant's token
                             config is chain='ethereum')
  --skip-onchain             Skip the on-chain supply comparison stage
  --no-open                  Don't prompt to open the XRPL explorer
  --json                     Output the full structured result as JSON
  -h, --help                 Show this help

EXIT CODES:
  0   VERDICT: PASS
  1   VERDICT: FAIL
  2   invocation error

PROTOCOL:
  https://github.com/Lazy-Jack-Ltd/bipcircle/blob/main/Documentation/architecture/public-reserve-verifier-protocol.md
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { printHelp(); process.exit(0); }
  if (!args['xrpl-tx']) {
    process.stderr.write('error: --xrpl-tx is required\n');
    printHelp();
    process.exit(2);
  }
  const hasTenant = Boolean(args.tenant);
  const hasUnsafe = Boolean(args['unsafe-bank-service-url']) && Boolean(args['unsafe-issuer']);
  if (!hasTenant && !hasUnsafe) {
    process.stderr.write('error: either --tenant <id> OR (--unsafe-bank-service-url AND --unsafe-issuer) is required\n');
    printHelp();
    process.exit(2);
  }

  let result;
  try {
    result = await verify({
      txHash: args['xrpl-tx'],
      tenantId: args.tenant,
      bankServiceUrl: args['unsafe-bank-service-url'],
      xrplIssuerAddress: args['unsafe-issuer'],
      network: args.network || 'mainnet',
      rpcUrl: args['rpc-url'],
      ethRpcUrl: args['eth-rpc-url'],
      skipOnChainSupply: args['skip-onchain'] === true,
    });
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n`);
    process.exit(2);
  }

  if (args.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    process.stdout.write(`\nVERDICT: ${result.verdict}\n`);
    if (result.stages.witness) {
      process.stdout.write(`  asOfDate: ${result.stages.witness.asOfDate}\n`);
      process.stdout.write(`  tenantId: ${result.stages.witness.tenantId}\n`);
      process.stdout.write(`  sealCount: ${result.stages.witness.sealCount}\n`);
    }
    if (result.stages.signatures) {
      process.stdout.write(`  signatures: ${result.stages.signatures.sealsVerified}/${result.stages.signatures.sealsTotal} OK\n`);
    }
    if (result.stages.merkle) {
      process.stdout.write(`  merkle root: ${result.stages.merkle.ok ? 'OK' : 'MISMATCH'}\n`);
    }
    if (result.stages.supply && !result.stages.supply.skipped) {
      const s = result.stages.supply;
      if (s.ok) {
        process.stdout.write(`  reserves: ${s.reservesMinorUnits} | supply: ${s.onChainSupplyMinorUnits} | match: ✓\n`);
      } else {
        process.stdout.write(`  reserves: ${s.reservesMinorUnits} | supply: ${s.onChainSupplyMinorUnits} | SHORTFALL: ${s.shortfallMinorUnits}\n`);
      }
    } else if (result.stages.supply?.skipped) {
      process.stdout.write(`  supply check: SKIPPED (${result.stages.supply.reason})\n`);
    }
    if (result.failures.length > 0) {
      process.stdout.write(`\nFAILURES:\n`);
      for (const f of result.failures) {
        process.stdout.write(`  [${f.stage}] ${f.reason}\n`);
      }
    }

    const url = explorerUrl(args['xrpl-tx'], args.network || 'mainnet');
    process.stdout.write(`\nView on XRPL: ${url}\n`);
    if (args['no-open'] !== true) {
      await promptOpen(url);
    }
  }

  process.exit(result.verdict === 'PASS' ? 0 : 1);
}

main().catch((err) => {
  process.stderr.write(`fatal: ${err.message}\n${err.stack}\n`);
  process.exit(2);
});
