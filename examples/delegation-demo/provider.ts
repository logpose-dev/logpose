import type { Server } from 'node:http';
import cors from 'cors';
import express, { type Express, type Request, type Response } from 'express';

import { serveExpress } from '@logpose-dev/a2a';
import {
  createAttestor,
  MemoryStore,
  type AttestationPayload,
  type Attestor,
  type Credential,
} from '@logpose-dev/logpose';

import { ui } from './ui.js';

export const PROVIDER_PORT = 3001;

type AttestorWithExport = Attestor & {
  exportCredentials(): Promise<Credential[]>;
};

export interface ProviderRuntime {
  baseUrl: string;
  did: string;
  stop(): Promise<void>;
}

export async function startProvider(port = PROVIDER_PORT): Promise<ProviderRuntime> {
  const baseUrl = `http://localhost:${port}`;
  const app = express();

  app.use(cors());
  app.use(express.json());

  const attestor = await createAttestor({ store: new MemoryStore() });
  await seedMockCredentials(attestor, baseUrl);

  // `serveExpress` expects an attestor with `exportCredentials()`.
  // We adapt the core attestor by mapping that method to `list()`.
  app.use(serveExpress(withExportCredentials(attestor)));

  app.post('/task', (req: Request, res: Response) => {
    // This endpoint simulates the provider's real "work" surface.
    console.log(`${ui.agentATag} Received delegated task payload: ${ui.json(JSON.stringify(req.body))}`);

    res.json({
      ok: true,
      handledBy: 'Agent A (Provider)',
      message: 'Task completed successfully by provider agent.',
      receivedPayload: req.body,
    });
  });

  app.use((error: unknown, _req: Request, res: Response, _next: express.NextFunction) => {
    res.status(500).json({
      error: 'Provider middleware error',
      details: toMessage(error),
    });
  });

  const server = await listen(app, port);

  console.log(`${ui.agentATag} ${ui.success('Provider server booted.')}`);
  console.log(`${ui.agentATag} ${ui.label('URL:')} ${ui.value(baseUrl)}`);
  console.log(`${ui.agentATag} ${ui.label('DID:')} ${ui.value(attestor.did)}`);
  console.log(
    `${ui.agentATag} ${ui.label('Well-known credentials endpoint:')} ${ui.value(`${baseUrl}/.well-known/logpose.json`)}`,
  );

  return {
    baseUrl,
    did: attestor.did,
    stop: () => closeServer(server),
  };
}

async function seedMockCredentials(attestor: Attestor, audience: string): Promise<void> {
  // Both credentials are audience-bound to the provider URL.
  // This lets Agent B enforce replay-resistant delegation checks.
  const mockTasks: AttestationPayload[] = [
    {
      task: 'code-review',
      outcome: 'approved',
      evidence: {
        repository: 'acme/payments-api',
        pullRequest: 42,
        findingCount: 0,
      },
    },
    {
      task: 'code-review',
      outcome: 'approved',
      evidence: {
        repository: 'acme/dashboard-web',
        pullRequest: 77,
        findingCount: 1,
      },
    },
  ];

  for (const [index, payload] of mockTasks.entries()) {
    const credential = await attestor.record(payload, { aud: audience });
    console.log(
      `${ui.agentATag} Seeded credential ${ui.value(String(index + 1))}/${ui.value(String(mockTasks.length))}: ${ui.value(credential.id)} ${ui.subheading(`(aud=${audience})`)}`,
    );
  }
}

function withExportCredentials(attestor: Attestor): AttestorWithExport {
  const attestorWithExport = attestor as AttestorWithExport;

  if (typeof attestorWithExport.exportCredentials !== 'function') {
    attestorWithExport.exportCredentials = async () => attestor.list();
  }

  return attestorWithExport;
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

function toMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}
