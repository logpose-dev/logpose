import * as logpose from '@logpose-dev/logpose';
import type { Attestor, Credential } from '@logpose-dev/logpose';

const LOGPOSE_PROTOCOL = 'logpose-v1';
const WELL_KNOWN_PATH = '/.well-known/logpose.json';
const CORS_HEADER_NAME = 'Access-Control-Allow-Origin';
const CORS_ALLOW_ALL = '*';
const JSON_CONTENT_TYPE = 'application/json';

type AttestorWithExport = Attestor & {
  exportCredentials(): Promise<Credential[]>;
};

interface VerifyBatchOptions {
  expectedAudience: string;
}

interface NormalizedBatchResult {
  valid: boolean;
  revoked: boolean;
  reasons: string[];
}

type VerifyBatchFunction = (
  credentials: Credential[],
  options: VerifyBatchOptions,
) => Promise<unknown>;

interface ExpressRequestLike {
  method?: string;
  path?: string;
  originalUrl?: string;
  url?: string;
}

interface ExpressResponseLike {
  header(name: string, value: string): this;
  json(payload: unknown): this;
}

type NextFunction = (error?: unknown) => void;

export interface AgentCardFragment {
  reputation: Reputation;
}

export interface Reputation {
  protocol: typeof LOGPOSE_PROTOCOL;
  did: string;
  credentials_endpoint: string;
  summary?: ReputationSummary;
}

export interface ReputationSummary {
  total_credentials: number;
  oldest: string | null;
  skills_attested: string[];
}

export interface AdvertiseOptions {
  agentUrl?: string;
  includeSummary?: boolean;
}

export interface LegacyAgentCardFragment {
  protocolVersion: string;
  endpoint: typeof WELL_KNOWN_PATH;
  did: string;
}

export interface TrustSummary {
  isTrusted: boolean;
  valid: number;
  revoked: number;
  reasons: string[];
}

export async function advertise(
  attestor: Attestor,
  options: AdvertiseOptions = {},
): Promise<AgentCardFragment> {
  const reputation: Reputation = {
    protocol: LOGPOSE_PROTOCOL,
    did: attestor.did,
    credentials_endpoint: resolveCredentialsEndpoint(options.agentUrl),
  };

  if (options.includeSummary !== false) {
    reputation.summary = await buildSummary(attestor);
  }

  return {
    reputation,
  };
}

export function advertiseLegacy(attestor: Attestor): LegacyAgentCardFragment {
  return {
    protocolVersion: '1.0.0',
    endpoint: WELL_KNOWN_PATH,
    did: attestor.did,
  };
}

export function serve(attestor: AttestorWithExport): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    const pathname = parsePathname(request.url);
    if (request.method !== 'GET' || pathname !== WELL_KNOWN_PATH) {
      return new Response('Not Found', { status: 404 });
    }

    try {
      const credentials = await attestor.exportCredentials();
      return createJsonResponse(credentials, 200, true);
    } catch (error) {
      const message = `Failed to export credentials: ${toMessage(error)}`;
      return createJsonResponse({ error: message }, 500, true);
    }
  };
}

export function serveExpress(
  attestor: AttestorWithExport,
): (req: ExpressRequestLike, res: ExpressResponseLike, next: NextFunction) => Promise<void> {
  return async (req: ExpressRequestLike, res: ExpressResponseLike, next: NextFunction): Promise<void> => {
    const pathname = req.path ?? parsePathname(req.originalUrl ?? req.url);
    if (req.method !== 'GET' || pathname !== WELL_KNOWN_PATH) {
      next();
      return;
    }

    try {
      const credentials = await attestor.exportCredentials();
      res.header(CORS_HEADER_NAME, CORS_ALLOW_ALL);
      res.json(credentials);
    } catch (error) {
      next(error);
    }
  };
}

export async function evaluate(agentUrl: string): Promise<TrustSummary> {
  const reasons = new Set<string>();
  let valid = 0;
  let revoked = 0;

  const wellKnownUrl = buildWellKnownUrl(agentUrl);
  if (!wellKnownUrl) {
    reasons.add('Invalid agent URL');
    return toTrustSummary(valid, revoked, reasons);
  }

  let payload: unknown;
  try {
    const response = await fetch(wellKnownUrl.toString(), {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      reasons.add(`Credential fetch failed with HTTP ${response.status}`);
      return toTrustSummary(valid, revoked, reasons);
    }

    payload = await response.json();
  } catch (error) {
    reasons.add(`Credential fetch failed: ${toMessage(error)}`);
    return toTrustSummary(valid, revoked, reasons);
  }

  if (!Array.isArray(payload)) {
    reasons.add('Credential payload is not an array');
    return toTrustSummary(valid, revoked, reasons);
  }

  const credentials = payload as Credential[];
  if (credentials.length === 0) {
    reasons.add('No credentials published by target agent');
    return toTrustSummary(valid, revoked, reasons);
  }

  const verifyBatch = getVerifyBatch();
  if (!verifyBatch) {
    reasons.add('Core SDK does not expose verifyBatch');
    return toTrustSummary(valid, revoked, reasons);
  }

  try {
    const rawResults = await verifyBatch(credentials, { expectedAudience: agentUrl });
    if (!Array.isArray(rawResults)) {
      reasons.add('verifyBatch returned an invalid result shape');
      return toTrustSummary(valid, revoked, reasons);
    }

    for (const rawResult of rawResults) {
      const result = normalizeBatchResult(rawResult);
      if (result.valid) {
        valid += 1;
      }
      if (result.revoked) {
        revoked += 1;
      }
      if (result.reasons.length > 0) {
        for (const reason of result.reasons) {
          reasons.add(reason);
        }
      } else if (!result.valid) {
        reasons.add('Credential failed verification');
      }
    }

    if (rawResults.length !== credentials.length) {
      reasons.add('verifyBatch result count mismatch');
    }
  } catch (error) {
    reasons.add(`Batch verification failed: ${toMessage(error)}`);
  }

  return toTrustSummary(valid, revoked, reasons);
}

function createJsonResponse(payload: unknown, status: number, includeCors: boolean): Response {
  const headers = new Headers({
    'Content-Type': JSON_CONTENT_TYPE,
  });
  if (includeCors) {
    headers.append(CORS_HEADER_NAME, CORS_ALLOW_ALL);
  }

  return new Response(JSON.stringify(payload), {
    status,
    headers,
  });
}

function buildWellKnownUrl(agentUrl: string): URL | undefined {
  try {
    return new URL(WELL_KNOWN_PATH, new URL(agentUrl));
  } catch {
    return undefined;
  }
}

function resolveCredentialsEndpoint(agentUrl: string | undefined): string {
  if (!agentUrl) {
    return WELL_KNOWN_PATH;
  }

  const wellKnown = buildWellKnownUrl(agentUrl);
  if (!wellKnown) {
    return WELL_KNOWN_PATH;
  }

  return wellKnown.toString();
}

async function buildSummary(attestor: Attestor): Promise<ReputationSummary> {
  const credentials = await attestor.list();
  const skills = new Set<string>();
  let oldestTimestamp = Number.POSITIVE_INFINITY;
  let oldest: string | null = null;

  for (const credential of credentials) {
    const task = credential.credentialSubject.task;
    if (typeof task === 'string' && task.length > 0) {
      skills.add(task);
    }

    const validFrom = Date.parse(credential.validFrom);
    if (Number.isFinite(validFrom) && validFrom < oldestTimestamp) {
      oldestTimestamp = validFrom;
      oldest = credential.validFrom;
    }
  }

  return {
    total_credentials: credentials.length,
    oldest,
    skills_attested: [...skills].sort(),
  };
}

function getVerifyBatch(): VerifyBatchFunction | undefined {
  const maybeVerifyBatch = (logpose as { verifyBatch?: unknown }).verifyBatch;
  if (typeof maybeVerifyBatch !== 'function') {
    return undefined;
  }

  return maybeVerifyBatch as VerifyBatchFunction;
}

function normalizeBatchResult(value: unknown): NormalizedBatchResult {
  if (!isRecord(value)) {
    return {
      valid: false,
      revoked: false,
      reasons: ['Invalid verification result entry'],
    };
  }

  const valid = value.valid === true;
  const revoked = value.revoked === true;
  const reasons: string[] = [];

  if (typeof value.reason === 'string' && value.reason.length > 0) {
    reasons.push(value.reason);
  }

  if (Array.isArray(value.reasons)) {
    for (const reason of value.reasons) {
      if (typeof reason === 'string' && reason.length > 0) {
        reasons.push(reason);
      }
    }
  }

  return { valid, revoked, reasons };
}

function toTrustSummary(valid: number, revoked: number, reasons: Set<string>): TrustSummary {
  return {
    isTrusted: valid > 0 && revoked === 0,
    valid,
    revoked,
    reasons: [...reasons],
  };
}

function parsePathname(urlLike: string | undefined): string | undefined {
  if (!urlLike) {
    return undefined;
  }

  try {
    return new URL(urlLike, 'http://localhost').pathname;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function toMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}
