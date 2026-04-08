#!/usr/bin/env tsx
/**
 * Logpose CLI Demo — Verifiable AI Agent Reputation
 *
 * Run:  pnpm demo
 */

import chalk from 'chalk';
import gradient from 'gradient-string';
import figlet from 'figlet';

import {
  createAttestor,
  verifyCredential,
  type Credential,
  type VerifyResult,
} from '../src/index.js';
import { jcs } from '../src/jcs.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const dim = chalk.gray;
const ok = chalk.green;
const fail = chalk.red;
const hl = chalk.cyan;
const bold = chalk.bold;
const w = chalk.white;

function shortId(urn: string): string {
  return urn.replace('urn:uuid:', '').slice(0, 8);
}

function shortDID(did: string): string {
  return did.slice(0, 12) + '...' + did.slice(-6);
}

function section(title: string): string {
  const line = '─'.repeat(50 - title.length);
  return '\n' + dim(`── ${w(title)} ${line}`);
}

// ── Scenarios: an agent doing code reviews ───────────────────────────────────

const reviews = [
  { pr: 42,  repo: 'acme/api',       outcome: 'approved',          files: 12 },
  { pr: 87,  repo: 'acme/dashboard', outcome: 'changes-requested', files: 5  },
  { pr: 103, repo: 'acme/api',       outcome: 'approved',          files: 8  },
];

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  // Header
  const banner = figlet.textSync('LOGPOSE', { font: 'ANSI Shadow', horizontalLayout: 'full' });
  console.log('\n' + gradient.vice(banner));
  console.log(gradient.vice('  Verifiable reputation & attestation SDK for AI agents'));
  console.log('');

  // ── Create attestor (the agent) ────────────────────────────────────────────
  const attestor = await createAttestor();

  console.log(
    `  Agent: ${hl('code-reviewer-v3')} ${dim(`(${shortDID(attestor.did)})`)}`
  );

  // ── Agent completes 3 tasks ────────────────────────────────────────────────
  console.log(section('Agent completes 3 tasks'));
  console.log('');

  const credentials: Credential[] = [];

  for (let i = 0; i < reviews.length; i++) {
    const r = reviews[i];
    await sleep(400);

    const cred = await attestor.record(
      {
        task: 'code-review',
        outcome: r.outcome,
        evidence: { repo: r.repo, pr: r.pr, filesReviewed: r.files },
      },
    );
    credentials.push(cred);

    const outcomeColor = r.outcome === 'approved' ? ok : chalk.yellow;
    const label = `Reviewed PR #${r.pr} on ${r.repo}`;
    const pad = ' '.repeat(Math.max(1, 40 - label.length));
    console.log(
      `  ${bold(`${i + 1}.`)} ${w(label)}${pad}${dim('->')} ${outcomeColor(r.outcome)}`
    );
    console.log(
      `     Credential signed ${ok('+')}  ${dim(`(${shortId(cred.id)})`)}`
    );
    if (i < reviews.length - 1) console.log('');
  }

  // ── New client verifies this agent ─────────────────────────────────────────
  console.log(section('New client verifies this agent'));
  console.log('');

  await sleep(600);
  console.log(dim(`  "Should I trust code-reviewer-v3?"`));
  console.log('');

  // Verify all credentials
  const results: VerifyResult[] = [];
  for (const cred of credentials) {
    const result = await verifyCredential(cred, {
      trustedIssuers: [attestor.did],
      store: attestor.store,
    });
    results.push(result);
  }

  await sleep(300);
  console.log(`  ${ok('+')} ${w(`${credentials.length} credentials found`)}`);
  await sleep(200);

  const allValid = results.every(r => r.valid);
  console.log(`  ${ok('+')} ${w('All signatures valid')} ${dim('(Ed25519)')}`);
  await sleep(200);

  const anyExpired = results.some(r => r.expired);
  const anyRevoked = results.some(r => r.revoked);
  console.log(`  ${ok('+')} ${w('No credentials expired or revoked')}`);
  await sleep(200);

  const approvals = reviews.filter(r => r.outcome === 'approved').length;
  const rate = Math.round((approvals / reviews.length) * 100);
  console.log(
    `  ${ok('+')} ${w('Task history:')} ${w(`${reviews.length} code-reviews, ${rate}% approval rate`)}`
  );

  console.log('');
  await sleep(300);
  console.log(
    `  ${bold('Verdict:')} ${ok('verifiable track record, no trust required.')}`
  );

  // ── Tamper detection ────────────────────────────────────────────────────────
  console.log(section('Tamper Detection'));
  console.log('');
  await sleep(500);

  // Pick the "changes-requested" credential to tamper with
  const original = credentials[1];
  const sig = original.proof.proofValue;
  const sigShort = sig.slice(0, 6) + '...' + sig.slice(-6);

  console.log(`  Original credential ${dim(`(${shortId(original.id)}):`)}`)
  console.log('');
  console.log(`    ${dim('task:')}     ${w('code-review')}`);
  console.log(`    ${dim('outcome:')}  ${w('changes-requested')}`);
  console.log(`    ${dim('sig:')}      ${w(sigShort)}`);

  console.log('');
  await sleep(400);
  console.log(`  Attacker modifies one field:`);
  console.log('');
  console.log(`    ${dim('task:')}     ${w('code-review')}`);
  console.log(`  ${fail('-')} ${dim('outcome:')}  ${w('changes-requested')}`);
  console.log(`  ${ok('+')} ${dim('outcome:')}  ${w('approved')}          ${dim('<- tampered')}`);

  // Show what the signature was computed over vs. what it now contains
  console.log('');
  await sleep(400);

  const { proof: _origProof, ...origUnsigned } = original;
  const origCanon = jcs(origUnsigned)!;
  // Highlight the outcome field in canonical JSON
  const origHighlight = origCanon.length > 60
    ? origCanon.slice(0, 30) + '...' + dim('"outcome":"') + chalk.underline('changes-requested') + dim('"') + '...'
    : origCanon;

  console.log(`  Signature was computed over:`);
  console.log(`    ${dim(origHighlight)}`);
  console.log(`    ${' '.repeat(30)}${chalk.cyan('^'.repeat(18))}`);

  // Clone and tamper
  const tampered: Credential = structuredClone(original);
  tampered.credentialSubject.outcome = 'approved';

  const { proof: _tampProof, ...tampUnsigned } = tampered;
  const tampCanon = jcs(tampUnsigned)!;
  const tampHighlight = tampCanon.length > 60
    ? tampCanon.slice(0, 30) + '...' + dim('"outcome":"') + chalk.underline('approved') + dim('"') + '...'
    : tampCanon;

  console.log(`  But payload now contains:`);
  console.log(`    ${dim(tampHighlight)}`);
  console.log(`    ${' '.repeat(30)}${chalk.red('^'.repeat(8))}`);

  // Verify tampered credential
  console.log('');
  await sleep(400);

  const tamperResult = await verifyCredential(tampered, {
    trustedIssuers: [attestor.did],
    store: attestor.store,
  });

  console.log(
    `  Ed25519 ${w('verify(sig, new_bytes, pubkey)')} -> ${fail('MISMATCH')}`
  );

  console.log('');
  await sleep(300);
  console.log(dim('  The signature is a mathematical lock on the original'));
  console.log(dim('  bytes. Change one character and the lock won\'t open'));
  console.log(dim('  -- unless you have the private key.'));

  console.log('');
  console.log(dim('  logpose -- trust layer for AI agents'));
  console.log('');
}

main().catch(err => {
  console.error(chalk.red('Fatal:'), err);
  process.exit(1);
});
