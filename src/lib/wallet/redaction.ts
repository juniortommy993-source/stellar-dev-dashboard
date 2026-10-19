/**
 * Redaction utilities for wallet errors.
 *
 * Wallet errors can contain sensitive material: private keys, seed phrases,
 * signed transaction payloads, API tokens, addresses, and user identifiers.
 * This module provides a single, deterministic redaction pass that must be
 * applied before errors are sent to telemetry or included in a user export.
 *
 * Design notes:
 * - Pure functions only; no I/O, no global mutation, no dependencies.
 * - Redaction is best-effort and defense-red-under-depth: we prefer over-redaction
 *   to under-redaction. Never throw from the redaction path.
 * - Output is stable and deterministic so it can be snapshot-tested.
 */

export const REDACTED = '[REDACTED]' as const;

export interface RedactionOptions {
  /** Maximum depth to walk in nested objects/arrays. */
  maxDepth?: number;
  /** Maximum number of object keys to process per object. */
  maxKeys?: number;
  /** Maximum string length before truncation. */
  maxStringLength?: number;
}

const DEFAULT_MAX_DEPTH = 8;
const DEFAULT_MAX_KEYS = 200;
const DEFAULT_MAX_STRING_LENGTH = 4096;

/**
 * Keys whose values are always redacted regardless of content.
 * Matching is case-insensitive and substring-based (e.g. `authToken` matches `token`).
 */
const SENSITIVE_KEY_PATTERNS = [
  /private[_\-]?key/i,
  /secret/i,
  /seed/i,
  /mnemonic/i,
  /passphrase/i,
  /password/i,
  /passwd/i,
  /token/i,
  /api[_\-]?key/i,
  /secretkey/i,
  /authorization/i,
  /cookie/i,
  /session/i,
  /signature/i,
  /signed_transaction/i,
  /signedtransaction/i,
  /rawTransaction/i,
  /raw_transaction/i,
  /credential/i,
  /cvv/i,
  /card_number/i,
  /iban/i,
  /secret_key/i,
];

/**
 * Patterns that match sensitive values embedded in free text (error messages,
 * stack traces, urls, etc.). Each match is replaced with REDACTED.
 */
const SENSITIVE_VALUE_PATTERNS: RegExp[] = [
  // Ethereum-style 0x-prefixed hex (addresses, hashes, signatures, private keys).
  /0x[0-9a-fA-F]{40}/gi,
  // Base58-like keys / signatures (64+ chars).
  /\b[5-9][A-HJ-Za-kz0-9]{64},?\b/g,
  // JSON Web Tokens.
  /\beyJw[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[a-zA-Z0-9_-]+\b/g,
  // Bearer tokens in headers/strings.
  /\bBearer\s+[A-Za-z0-9._-]{8,}\b/gi,
  // Private key blocks.
  /-----BEGIN [A-Z]*PRIVATE KEY-----[\s\S]*?-----END [A-Z]*PRIVATE KEY-----/g,
  // Mnemonic phrases (12/24 words) following a keyword.
  /\b(?:mnemonic|seed\s*phrase|recovery\s*phrase)\s*[:=]\s*['"]?[a-z ]{20,}['"]?/gi,
];

/**
 * Truncates a string to a bounded length to avoid exporting huge payloads.
 */
function truncate(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  return `${value.slice(0, maxLength)}[ truncated ${value.length - maxLength} chars}`;
}

/**
 * Redacts sensitive substrings from a free-form string.
 */
export function redactString(
  input: string,
  options: RedactionOptions = {},
): string {
  if (typeof input !== 'string') return REDACTED;
  const maxLength = options.maxStringLength ?? DEFAULT_MAX_STRING_LENGTH;
  let out = truncate(input, maxLength);
  for (const pattern of SENSITIVE_VALUE_PATTERNS) {
    out = out.replace(pattern, REDACTED);
  }
  return out;
}

/**
 * Returns true if a object key is considered sensitive and its value must be
 * redacted wholesale.
 */
export function isSensitiveKey(key: string): boolean {
  if (!key) return false;
  return SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(key));
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Deep-redacts an arbitrary value for telemetry / export. Handles nested
 * objects, arrays, Error instances, Dates, BigInt, and primitives. Cycles are
 * detected and collapsed to a marker string.
 */
export function redactValue(
  value: unknown,
  options: RedactionOptions = {},
  _seen: WeakSet<object> = new WeakSet(),
  _depth = 0,
): unknown {
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;

  if (value === null || value === undefined) return value;

  const t = typeof value;
  if (t === 'string') return redactString(value as string, options);
  if (t === 'number' || t === 'boolean' || t === 'bigint') return value;
  if (t === 'symbol') return REDACTED;
  if (t === 'function') return REDACTED;

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? REDACTED : value.toISOString();
  }

  if (value instanceof Error) {
    return redactError(value, options);
  }

  if (typeof value === 'object') {
    const obj = value as object;
    if (_seen.has(obj)) return '[CIRCULAR]';
    if (_depth >= maxDepth) return '[TRUNCATED]';
    _seen.add(obj);
    try {
      if (Array.isArray(value)) {
        return value
          .slice(0, maxKeys)
          .map((item) => redactValue(item, options, _seen, _depth + 1));
      }
      if (isPlainObject(value)) {
        const out: Record<string, unknown> = {};
        const keys = Object.keys(value as Record<string, unknown>);
        for (const key of keys.slice(0, maxKeys)) {
          if (isSensitiveKey(key)) {
            out[key] = REDACTED;
          } else {
            out[key] = redactValue(
              (value as Record<string, unknown>)[key],
              options,
              _seen,
              _depth + 1,
            );
          }
        }
        return out;
      }
      // Non-plain objects (class instances, Map, Set, etc.) are not safe to
      // serialize directly; collapse to a type marker.
      return `[${obj.constructor ?? Object}.name]`;
    } finally {
      _seen.delete(obj);
    }
  }

  return REDACTED;
}

/**
 * Redacts an Error instance into a plain, serializable object suitable for
 * telemetry and user export. Preserves name/message/stack (but redacted),
 * cause chain, and custom enumerable properties.
 */
export interface RedactedError {
  name: string;
  message: string;
  stack?: string;
  code?: string | number;
  cause?: unknown;
  details?: Record<string, unknown>;
  [key: string]: unknown;
}

export function redactError(
  error: unknown,
  options: RedactionOptions = {},
  _seen: WeakSet<object> = new WeakSet(),
  _depth = 0,
): RedactedError {
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;

  if (!(error instanceof Error)) {
    return {
      name: 'Error',
      message: typeof error === 'string' ? redactString(error, options) : REDACTED,
    };
  }

  if (_seen.has(error)) {
    return { name: error.name || 'Error', message: '[CIRCULAR]' };
  }
  _seen.add(error);

  const result: RedactedError = {
    name: redactString(error.name || 'Error', options),
    message: redactString(error.message || '', options),
  };

  if (typeof error.stack === 'string') {
    result.stack = redactString(error.stack, options);
  }

  const errorWithCode = error as Error & { code?: unknown };
  if (typeof errorWithCode.code === 'string' || typeof errorWithCode.code === 'number') {
    result.code = errorWithCode.code as string | number;
  }

  const errorWithCause = error as Error & { cause?: unknown };
  if (errorWithCause !== undefined && 'cause' in error) {
    if (_depth >= maxDepth) {
      result.cause = '[TRUNCATED]';
    } else if (errorWithCause.cause instanceof Error) {
      result.cause = redactError(errorWithCause.cause, options, _seen, _depth + 1);
    } else {
      result.cause = redactValue(errorWithCause.cause, options, _seen, _depth + 1);
    }
  }

  // Custom enumerable properties (e.g. requestId, walletId, details).
  const customKeys = Object.keys(error as unknown as Record<string, unknown>).filter(
    (key) => key !== 'name' && key !== 'message' && key !== 'stack' && key !== 'code' && key !== 'cause',
  );
  const maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
  for (const key of customKeys.slice(0, maxKeys)) {
    if (isSensitiveKey(key)) {
      result[key] = REDACTED;
      continue;
    }
    const value = (error as unknown as Record<string, unknown>)[key];
    result[key] = redactValue(value, options, _seen, _depth + 1);
  }

  return result;
}

/**
 * Convenience wrapper for telemetry payloads that may contain an `error` field
 * along with other context. Returns a new object with all sensitive data
 * redacted. Never throws.
 */
export function redactTelemetryPayload(
  payload: Record<string, unknown>,
  options: RedactionOptions = {},
): Record<string, unknown> {
  try {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(payload)) {
      if (isSensitiveKey(key)) {
        out[key] = REDACTED;
        continue;
      }
      if (key === 'error' && value !== undefined && value !== null) {
        out[key] = redactError(value, options);
        continue;
      }
      out[key] = redactValue(value, options);
    }
    return out;
  } catch {
    // Redaction must never take down telemetry. Fail closed by returning a
    // fully redacted marker instead of the raw payload.
    return { error: REDACTED };
  }
}
