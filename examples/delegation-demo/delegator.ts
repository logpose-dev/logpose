import type { Server } from 'node:http';
import cors from 'cors';
import express, { type Express, type Request, type Response } from 'express';

import { evaluate, type TrustSummary } from '@logpose-dev/a2a';

import { ui } from './ui.js';

export const DELEGATOR_PORT = 3002;

export interface DelegatorRuntime {
  baseUrl: string;
  stop(): Promise<void>;
}

interface DelegatedTaskResponse {
  ok: boolean;
  handledBy: string;
  message: string;
  receivedPayload: unknown;
}

export async function startDelegator(port = DELEGATOR_PORT): Promise<DelegatorRuntime> {
  const baseUrl = `http://localhost:${port}`;
  const app = express();

  app.use(cors());
  app.use(express.json());

  app.get('/health', (_req: Request, res: Response) => {
    res.json({ ok: true, agent: 'Agent B (Delegator)' });
  });

  const server = await listen(app, port);

  console.log(`${ui.agentBTag} ${ui.success('Delegator server booted.')}`);
  console.log(`${ui.agentBTag} ${ui.label('URL:')} ${ui.value(baseUrl)}`);

  return {
    baseUrl,
    stop: () => closeServer(server),
  };
}

export async function attemptDelegation(targetAgentUrl: string): Promise<void> {
  console.log(ui.step(`[2/4] Agent B discovered Agent A at ${targetAgentUrl}`));
  console.log(
    `${ui.agentBTag} ${ui.label('Discovering credentials at')} ${ui.value(`${targetAgentUrl}/.well-known/logpose.json`)}`,
  );

  // `evaluate` fetches `/.well-known/logpose.json` and verifies
  // credential signatures, revocation, and expected audience.
  const trustSummary = await evaluate(targetAgentUrl);

  console.log(ui.step('[3/4] Agent B verified the credentials published by Agent A.'));
  printTrustSummary(trustSummary);

  if (!trustSummary.isTrusted) {
    // No trust, no delegation.
    console.warn(`${ui.agentBTag} ${ui.warning('Delegation aborted. Agent A is not trusted.')}`);
    return;
  }

  const taskPayload = {
    task: 'generate-release-notes',
    requestId: 'delegation-demo-001',
    context: {
      repo: 'acme/payments-api',
      releaseTag: 'v1.9.0',
    },
  };

  const response = await fetch(`${targetAgentUrl}/task`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(taskPayload),
  });

  if (!response.ok) {
    throw new Error(`Provider task endpoint failed with HTTP ${response.status}`);
  }

  const payload = (await response.json()) as DelegatedTaskResponse;

  console.log(ui.step('[4/4] Agent B delegated the task to Agent A successfully.'));
  console.log(`${ui.agentBTag} ${ui.label('Provider response:')} ${ui.success(payload.message)}`);
}

function printTrustSummary(summary: TrustSummary): void {
  console.log(
    `${ui.agentBTag} ${ui.label('Trust result:')} isTrusted=${ui.trustBoolean(summary.isTrusted)}`,
  );
  console.log(
    `${ui.agentBTag} ${ui.label('Valid credentials:')} ${ui.metric(summary.valid, true)}`,
  );
  console.log(
    `${ui.agentBTag} ${ui.label('Revoked credentials:')} ${ui.metric(summary.revoked)}`,
  );

  if (summary.reasons.length === 0) {
    console.log(`${ui.agentBTag} ${ui.label('Verification reasons:')} ${ui.success('none')}`);
    return;
  }

  console.log(`${ui.agentBTag} ${ui.label('Verification reasons:')}`);
  for (const reason of summary.reasons) {
    console.log(`  - ${ui.warning(reason)}`);
  }
}

function listen(app: Express, port: number): Promise<Server> {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, () => {
      resolve(server);
    });

    server.on('error', reject);
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}
