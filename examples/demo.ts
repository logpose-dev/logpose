#!/usr/bin/env tsx
/**
 * Logpose CLI Demo — Verifiable AI Agent Reputation
 *
 * Run:  pnpm tsx examples/demo.ts
 */

import chalk from 'chalk';
import gradient from 'gradient-string';
import boxen from 'boxen';
import ora from 'ora';
import figlet from 'figlet';
import Table from 'cli-table3';

import {
  createAttestor,
  verifyCredential,
  generateKeypair,
  createDID,
  createHolderBinding,
  type Credential,
  type VerifyResult,
} from '../src/index.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

function shortId(urn: string): string {
  return urn.replace('urn:uuid:', '').slice(0, 8);
}

function shortDID(did: string): string {
  return did.slice(0, 16) + '...' + did.slice(-6);
}

function badge(ok: boolean): string {
  return ok ? chalk.green('  PASS') : chalk.red('  FAIL');
}

function timestampShort(iso: string): string {
  return new Date(iso).toLocaleTimeString('en-US', {
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
}

// ── Credential scenarios ─────────────────────────────────────────────────────

const scenarios = [
  {
    task: 'code-review',
    outcome: 'approved',
    evidence: { repo: 'acme/api', pr: 342, filesReviewed: 12 },
  },
  {
    task: 'security-audit',
    outcome: 'passed',
    evidence: { target: 'auth-service', vulns: 0, scanDuration: '4m 12s' },
  },
  {
    task: 'data-pipeline-validation',
    outcome: 'healthy',
    evidence: { pipeline: 'etl-v3', rowsProcessed: 1_240_000, errors: 0 },
  },
  {
    task: 'api-integration-test',
    outcome: 'all-passing',
    evidence: { suite: 'payments-v2', tests: 87, failures: 0, coverage: '94%' },
  },
  {
    task: 'model-training-benchmark',
    outcome: 'above-threshold',
    evidence: { model: 'intent-clf-v4', accuracy: 0.972, latencyP99: '18ms' },
  },
];

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  // Header
  const banner = figlet.textSync('LOGPOSE', { font: 'ANSI Shadow', horizontalLayout: 'full' });
  console.log('\n' + gradient.vice(banner));
  console.log(
    gradient.vice('  Verifiable reputation & attestation SDK for AI agents\n'),
  );

  // ── Step 1: Create Attestor ────────────────────────────────────────────────
  const spin = ora({ text: chalk.cyan('Generating Ed25519 keypair & DID...'), spinner: 'dots12' }).start();
  await sleep(600);
  const attestor = await createAttestor();
  spin.succeed(chalk.green('Attestor created'));

  console.log(
    boxen(
      chalk.bold('Attestor Identity\n\n') +
      chalk.gray('DID        ') + chalk.white(shortDID(attestor.did)) + '\n' +
      chalk.gray('Key type   ') + chalk.white('Ed25519') + '\n' +
      chalk.gray('Method     ') + chalk.white('did:key'),
      { padding: 1, borderStyle: 'round', borderColor: 'cyan', dimBorder: true },
    ),
  );

  // ── Step 2: Record credentials ─────────────────────────────────────────────
  console.log('\n' + chalk.bold.cyan('  Recording credentials...\n'));

  const credentials: Credential[] = [];

  for (const scenario of scenarios) {
    const spin2 = ora({
      text: chalk.white(`  ${scenario.task}`),
      spinner: 'dots',
      indent: 2,
    }).start();
    await sleep(350);

    const cred = await attestor.record(scenario);
    credentials.push(cred);

    spin2.succeed(
      chalk.white(`  ${scenario.task}`) +
      chalk.gray(` → `) +
      chalk.yellow(scenario.outcome) +
      chalk.gray(`  (${shortId(cred.id)})`),
    );
  }

  // ── Step 3: Verify all credentials ─────────────────────────────────────────
  console.log('\n' + chalk.bold.cyan('  Verifying credentials...\n'));

  const results: VerifyResult[] = [];

  for (const cred of credentials) {
    const spin3 = ora({
      text: chalk.white(`  Verifying ${shortId(cred.id)}...`),
      spinner: 'dots',
      indent: 2,
    }).start();
    await sleep(250);

    const result = await verifyCredential(cred, {
      trustedIssuers: [attestor.did],
      store: attestor.store,
    });
    results.push(result);

    spin3.succeed(
      chalk.white(`  ${shortId(cred.id)}`) +
      chalk.gray(' → ') +
      (result.valid ? chalk.green.bold('VALID') : chalk.red.bold('INVALID')),
    );
  }

  // ── Step 4: Results table ──────────────────────────────────────────────────
  console.log('');

  const table = new Table({
    head: [
      chalk.cyan.bold('ID'),
      chalk.cyan.bold('Task'),
      chalk.cyan.bold('Outcome'),
      chalk.cyan.bold('Sig'),
      chalk.cyan.bold('Trusted'),
      chalk.cyan.bold('Expired'),
      chalk.cyan.bold('Revoked'),
      chalk.cyan.bold('Holder'),
      chalk.cyan.bold('Time'),
    ],
    style: { head: [], border: ['gray'] },
    chars: {
      'top': '─', 'top-mid': '┬', 'top-left': '┌', 'top-right': '┐',
      'bottom': '─', 'bottom-mid': '┴', 'bottom-left': '└', 'bottom-right': '┘',
      'left': '│', 'left-mid': '├', 'mid': '─', 'mid-mid': '┼',
      'right': '│', 'right-mid': '┤', 'middle': '│',
    },
  });

  for (const r of results) {
    const cred = r.credential;
    table.push([
      chalk.white(shortId(cred.id)),
      chalk.white(cred.credentialSubject.task),
      chalk.yellow(cred.credentialSubject.outcome),
      badge(r.valid),
      badge(r.issuerTrusted),
      badge(!r.expired),
      badge(!r.revoked),
      badge(r.holderVerified),
      chalk.gray(timestampShort(cred.validFrom)),
    ]);
  }

  console.log(table.toString());

  // ── Step 5: Summary box ────────────────────────────────────────────────────
  const total = results.length;
  const passed = results.filter(r => r.valid && r.issuerTrusted && !r.expired && !r.revoked).length;

  const summaryLines = [
    chalk.bold.white(`${passed}/${total} credentials fully verified\n`),
    chalk.gray('Signature     ') + chalk.green(`Ed25519Signature2024`),
    chalk.gray('DID method    ') + chalk.green(`did:key (base58btc)`),
    chalk.gray('Standard      ') + chalk.green(`W3C Verifiable Credentials 2.0`),
    chalk.gray('Revocation    ') + chalk.green(`LogposeRevocation`),
    chalk.gray('Canonical.    ') + chalk.green(`RFC 8785 (JCS)`),
    '',
    chalk.dim.italic('logpose — trust layer for AI agents'),
  ];

  console.log('\n' + boxen(summaryLines.join('\n'), {
    title: chalk.magenta.bold(' VERIFICATION SUMMARY '),
    titleAlignment: 'center',
    padding: 1,
    borderStyle: 'double',
    borderColor: 'magenta',
  }));

  console.log('');
}

main().catch(err => {
  console.error(chalk.red('Fatal:'), err);
  process.exit(1);
});
