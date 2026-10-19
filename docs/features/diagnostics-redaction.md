# Diagnostics Redaction

Implements **#774 — [2026 Security] Redact secrets and signed XDR from diagnostics**.

Secret keys, signed transaction envelopes (XDR), JWTs, API tokens, recovery
phrases and credential-bearing URLs must never reach telemetry, console logs,
error reports or `localStorage`. All diagnostics now pass through a single
redaction choke point: `src/lib/observability/redact.ts`.

## What is redacted

### By value shape (works anywhere in a string)

| Shape | Example | Detection |
| --- | --- | --- |
| Stellar secret seed | `S…` (56 chars) | `isStellarSecretKey` |
| Signed XDR envelope | `AAAA… (≼100 base64 chars) | `isSignedPdr` |
| JWT / JWS | `eyJ…`.`eyJ…`.… | `isJwt` |
| PEM private key | `-----BEGIN … PRIVATE KEY-----` | `isPemPrivateKey` |
| BIP-39 recovery phrase | 12/15/18/21/24 words | `isMnemonic` |
| Provider keys | `sk_live_…`, `ghp_…`, `github_pat…`, `xoxb-…`, `AIza… | `isProviderApiKey` |
| Auth header | `Bearer … `, `Basic …` | `isAuthHeaderValue` |

### By key name

Keys are split on `camelCase` / `snake_case` / `kebab-case` boundaries and
matched against credential segments (`secret`, `token`, `password`,
`authorization`, `privateKey`, `mnemonic`, `seed`, `xdr`, `envelope`, …).
Sensitive keys are replaced **wholesale** — the value is never inspected or
serialised. A key pair like `apiKey` is caught by the `key` + qualifier rule,
while `publicKey` is left intact.

### URLs

Credential query parameters (`token`, `access_token`, `api_key`, `secret`,
`signature`, `xdr`, `code`, …) are replaced with `[REDACTED]` in place, and the
rest of the URL is preserved. Malformed/relative URLs fall back to substring
scrubbing.

## API

```ts
import {
  redactValue,          // deep-redact a JSON-like payload
  redactString,         // scrub an arbitrary string
  redactUrl,            // scrub credential query params
  redactError,          // { name, message, stack, code } with secrets removed
  redactForTelemetry,   // alias of redactValue at the telemetry boundary
  withRedaction,        // wrap a logger so every call is redacted
  containsSensitiveValue,
} from '@/lib/observability/redact';
```

Options: `placeholder`, `maxDepth` (default 8), `maxStringLength` (default 10,000), `extraSensitiveKeys`.

## Integration

- **`src/utils/logger.ts`** — every entry redacts its message, context and
  `Error` before it is written to the console or handed to log handlers.
- **`src/lib/errorReporting.ts`** — `sanitizeErrorData` now deep-redacts the
  full details payload instead of deleting a fixed allowlist of props; error
  `message`/`stack`, breadcrumbs, warnings, performance context and the
  fingerprint input are all redacted before they are queued, printed or
  persisted to `localStorage`.

## Wallet error redaction

Wallet code must never ship raw error objects to telemetry or to a user
diagnostics export. The wallet boundary is implemented in
`src/lib/wallet/redactWalletError.ts` and exposes a single entry point:

```ts
import { redactWalletError } from '@/lib/wallet/redactWalletError';

const safe = redactWalletError(err);
// { name, message, stack, code, cause, context }
```

The helper:

- runs the full error (including `cause` chains and attached context) through
  `redactError` / `redactValue`, so secret seeds, signed XDR, JWTs and
  recovery phrases are removed even when they appear inside a nested cause;
- preserves the error `code` and `cause.code` so callers can still branch on
  wallet failure classes after redaction;
- never throws — hostile payloads degrade to the same `[Unrepresentable]`
  markers as the core redactor.

Telemetry and export call sites use it as follows:

```ts
// Telemetry boundary
reportError(redactWalletError(err));

// User diagnostics export
const export = buildDiagnosticsExport({
  errors: errors.map(redactWalletError),
});
```

Any wallet path that reports an error without going through this helper is
a bug. The core redactor remains the single choke point; the wallet helper
just adds wallet-specific shape handling (cause chains, code preservation) on
top of it.

## Failure handling

Redaction never throws:

- circular references become `[Circular]`;
- recursion past `maxDepth` becomes `[Truncated]`;
- functions, symbols and objects with throwing getters become
  `[Unrepresentable]`;
- `null`/`undefined`/numbers/booleans pass through untouched.

This guarantees the diagnostics pipeline can always flush, even when the
payload that triggered the error is itself hostile. The wallet helper inherits
this contract, so a wallet error with a cyclic or throwing `cause` still produces
a redacted, serialisable payload.

## Compatibility & migration notes

- No public API changed: `reportError`, `reportWarning`, `reportPerformance`,
  `addBreadcrumb` and the logger functions keep their signatures.
- Downstream dashboards should expect the literal `[REDACTED]` /
  `[Truncated]` / `[Circular]` markers in place of prior raw values.
- If a field is legitimately sensitive but its name is not covered by the
  heuristics, add it via `extraSensitiveKeys` rather than disabling redaction.
- Redaction is intentionally conservative: false positives (over-redaction)
  are preferred over leaking a key. Because of that, an `xdr` key is redacted
  even when it holds an unsigned envelope.
- Wallet error `code` values are preserved, so existing error-classification
  logic continues to work against redacted payloads.

## Tests

`src/lib/observability/__tests__/redact.test.ts` covers:

- **Primary flow** — secret keys, signed XDR, mnemonics, provider keys and
  auth headers are removed from nested payloads; `withRedaction` scrubs logger
  messages, context and errors.
- **Boundary cases** — near-miss strings (short keys, truncated XDR, 11-word
  phrases), non-sensitive values, URL query-param scrubbing, depth and length
  truncation.
- **Failure paths** — circular references, `Error` message/stack redaction,
  malformed and hostile input (throwing getters), `null`/`undefined`.

`src/lib/wallet/__tests__/redactWalletError.test.ts` covers the wallet
boundary:

- **Primary flow** — a wallet error carrying a secret seed and signed XDR in
  its message and context is redacted before telemetry and export, while the
  code of the error and the code of its cause are preserved.
- **Boundary case** — a wallet error with a non-sensitive message and no context
  passes through with its message intact, and `publicKey` context is not
  over-redacted.
- **Failure path** — a cause chain containing a circular reference and a
  throwing getter is redacted without throwing, producing `[Circular]` /
  `[Unrepresentable]` markers.
