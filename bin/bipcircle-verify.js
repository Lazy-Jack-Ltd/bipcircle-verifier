#!/usr/bin/env node
/**
 * bipcircle-verify — open-source CLI for the BIPCircle public-reserve-
 * verifier protocol v1.
 *
 *   bipcircle-verify --xrpl-tx <hash> --bank-service-url <url> [opts]
 *
 * Returns:
 *   exit 0 + "VERDICT: PASS" on the happy path
 *   exit 1 + "VERDICT: FAIL" with a structured diff on failure
 *
 * Supports --json for machine-readable output (the same structured
 * result the programmatic verify() returns).
 */

'use strict';

import { verify } from '../src/index.js';

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { args.help = true; continue; }
    if (a === '--json') { args.json = true; continue; }
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const val = argv[i + 1];
      args[key] = val;
      i += 1;
    }
  }
  return args;
}

function printHelp() {
  process.stdout.write(`bipcircle-verify — public-reserve-verifier protocol v1

USAGE:
  bipcircle-verify --xrpl-tx <hash> --bank-service-url <url> [options]

REQUIRED:
  --xrpl-tx <hash>          64-hex XRPL transaction hash for the daily
                            treasury attestation you want to verify
  --bank-service-url <url>  Per-tenant bank-service base URL (the
                            verifier fetches /.well-known/bank-service-keys
                            from here). E.g. https://bank-service-tvvin.run.app

OPTIONS:
  --network <name>          "mainnet" (default) | "testnet"
  --rpc-url <url>            Override XRPL JSON-RPC endpoint
  --json                     Output the full structured result as JSON
                             (default: human-readable summary)
  -h, --help                 Show this help

EXIT CODES:
  0   VERDICT: PASS
  1   VERDICT: FAIL (or invocation error)

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
  if (!args['bank-service-url']) {
    process.stderr.write('error: --bank-service-url is required\n');
    printHelp();
    process.exit(2);
  }

  let result;
  try {
    result = await verify({
      txHash: args['xrpl-tx'],
      network: args.network || 'mainnet',
      bankServiceUrl: args['bank-service-url'],
      rpcUrl: args['rpc-url'],
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
    if (result.failures.length > 0) {
      process.stdout.write(`\nFAILURES:\n`);
      for (const f of result.failures) {
        process.stdout.write(`  [${f.stage}] ${f.reason}\n`);
      }
    }
  }

  process.exit(result.verdict === 'PASS' ? 0 : 1);
}

main().catch((err) => {
  process.stderr.write(`fatal: ${err.message}\n${err.stack}\n`);
  process.exit(2);
});
