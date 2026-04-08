import canonicalize from 'canonicalize';

/**
 * RFC 8785 JSON Canonicalization Scheme.
 * Cast needed because `canonicalize` is CJS and nodenext resolves
 * the default import as the module namespace.
 */
export const jcs = canonicalize as unknown as (input: unknown) => string | undefined;
