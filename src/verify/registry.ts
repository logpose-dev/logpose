const trustedIssuers = new Set<string>();

export function trustIssuer(did: string): void {
  trustedIssuers.add(did);
}

export function untrustIssuer(did: string): void {
  trustedIssuers.delete(did);
}

export function isTrustedIssuer(did: string): boolean {
  if (trustedIssuers.size === 0) return true;
  return trustedIssuers.has(did);
}

export function loadRegistry(dids: string[]): void {
  trustedIssuers.clear();
  for (const did of dids) {
    trustedIssuers.add(did);
  }
}

export function exportRegistry(): string[] {
  return [...trustedIssuers];
}
