# Named outbound service targets

`Services\ServiceTokenManager` selects a trusted, immutable `service_targets` definition independently of browser consumers and inbound `ResourceVerifier`. Every worker remains bound to one resource application at the provider. Calling two applications requires two separately registered target workers; a caller cannot choose an audience or borrow browser/resource credentials.

Use the canonical root configuration and populate secrets from the host's existing private environment or secret manager. Each target has all of these fields:

```php
'service_targets' => [
    'documents' => [
        'origin' => 'https://identity.example',
        'application_id' => 'documents',
        'base_url' => 'https://documents.example/api',
        'client_id' => env('DOCUMENTS_WORKER_ID'),
        'client_secret' => env('DOCUMENTS_WORKER_SECRET'),
        'scopes' => ['documents.read', 'documents.write'],
        'cache_store' => 'redis',
        'http' => ['ca_bundle' => null, 'max_response_bytes' => 131072],
    ],
    'billing' => [
        'origin' => 'https://identity.example',
        'application_id' => 'billing',
        'base_url' => 'https://billing.example/v1',
        'client_id' => env('BILLING_WORKER_ID'),
        'client_secret' => env('BILLING_WORKER_SECRET'),
        'scopes' => ['invoices.read'],
        'cache_store' => 'redis',
        'http' => ['ca_bundle' => null, 'max_response_bytes' => 131072],
    ],
],
```

`base_url` is required and validated as a fixed HTTPS URL without userinfo, query, fragment, traversal or encoded path segments. The helper treats its path as a directory, with or without a trailing slash. Definitions come from trusted host configuration, never request fields. Restart/reconstruct the registry after credential rotation; an existing target retains its original immutable definition.

```php
use IdentityPlatform\Laravel\Services\ServiceTokenManager;

$documents = app(ServiceTokenManager::class)->target('documents');
$response = $documents->request('documents/123?format=summary', [
    'scopes' => ['documents.read'],
]);
// Handle the domain status/payload and resource authorization in the host.

$token = $documents->token(['documents.read']);
$documents->reject($token, ['documents.read']); // Exact local generation only.
$documents->revoke($token);                   // Issuing-worker remote revocation.
```

Unknown target names fail before transport. Omitted scopes request the target's configured permitted set. Explicit empty, duplicate, interactive, malformed or unconfigured scopes fail before cache or HTTP access. Returned scopes must exactly match the normalized request. Native `client_credentials` issuance uses only the fixed service issuer (`origin/api/service-auth`), its `/oauth2/token` endpoint, worker Basic credentials and `urn:identity-platform:application:<application_id>` resource. No other credential family or audience is tried after failure. Tokens remain opaque; the package does not decode claims to create authority. The downstream resource must independently verify the token and domain permission.

## Encrypted cache and generations

The `identity:service:v2` namespace intentionally ignores older unindexed entries. Cache keys and acquisition locks bind the exact issuer, resource audience, client ID, credential fingerprint and sorted requested scopes. Index keys bind that authority and a token digest. Both token entries and lookup indexes use Laravel's authenticated `Crypt` encryption; index records contain a digest, never plaintext tokens. Decrypted records must match their target, scope-derived cache key, generation and bounded deadline. Swapped/corrupt entries or indexes cannot authorize cache reuse.

The response lifetime is an integer from 1 through 300 seconds measured from request start. Optional integer `expires_at` can only shorten it. Refresh/ID tokens, unknown response fields, missing/mismatched scopes and malformed Bearer tokens fail. A token stops being reusable five seconds before expiry. Indexes expire by the original token deadline.

Publication confirms the encrypted index write **before** writing a reusable token. Cache `put=false` and exceptions fail truthfully. An index write may commit and then fail, leaving a bounded orphan index; it cannot authorize token reuse. A token write may commit and then fail; its already-confirmed index allows later recovery and correct revocation. No multi-key transaction is assumed. Reuse verifies the matching encrypted index as well as the token entry.

`reject` compares the exact token under its scope-bound acquisition lock. `revoke` captures the encrypted index, sends one revocation request to the issuing worker endpoint, then compares the indexed token/generation under that same acquisition lock. A delayed old response cannot evict a successor, another scope/target or rotated credential. A missing/corrupt index allows the remote revocation but cannot select an arbitrary local entry to delete. Remote failure retains the locally cached credential; the remote outcome may be unknown and must be reconciled by the host.

All workers sharing these entries must use the same encryption keys and atomic cache/lock namespace. Configure an actual shared store for multi-process deployments. The implementation uses 30-second lock leases and waits at most five seconds to acquire them; the provider HTTP exchange is bounded to five seconds. Production cache operations must complete within the remaining lease, and the adapter must report write acknowledgement truthfully. Adapter availability, latency, lock expiry/ownership, encryption-key rotation and synchronized clocks require host qualification. An array store is process-local and is not a shared production cache.

## Guarded downstream requests

`request(relativePath, options)` returns a buffered PSR-7 response. Options are only `scopes`, `method`, `headers` and `body`. Methods are GET, HEAD, POST, PUT, PATCH and DELETE. Bodies are strings of at most 64 KiB; GET/HEAD cannot have a body. Header names are unique case-insensitively and total caller header bytes are limited to 16 KiB.

Paths are canonical relative paths beneath the configured base. Absolute/root-relative URLs, userinfo/origin switches, dot segments, duplicate separators, backslashes, fragments, percent-encoded path segments and control/non-ASCII bytes refuse before token acquisition. Queries are supported, with valid percent escapes. The helper canonicalizes the accepted base and query before acquiring a token, validates the resulting authority and base-path binding, then sends and compares that same URI. Uppercase DNS names and explicit HTTPS port 443 normalize to their equivalent authority; query brackets receive standard percent encoding. The host still chooses authorized domain endpoints; this helper cannot constrain a downstream application's internal proxy behavior.

Caller Authorization, Cookie, Host, Origin, Referer, forwarding, proxy/security and hop-by-hop transport overrides refuse. The separate downstream transport attaches only the issued Bearer token, disables cookies and redirects, verifies TLS, rejects redirect responses and unexpected effective URLs, and never receives worker Basic credentials. It bounds response reads to the configured `http.max_response_bytes`, capped at 1 MiB (default 128 KiB), and a five-second exchange budget. Provider credential transport remains the existing `Support\IdentityHttp` owner. Both downstream requests and that owner's service-target branch construct pending requests without Laravel global HTTP options or middleware, so ambient cookies, auth, Host overrides, destination rewrites and retry middleware cannot alter these exchanges. Laravel fake/recording hooks remain available. Host global configuration is restored immediately after request construction, before any HTTP exchange; browser/resource/consumer transport behavior is unchanged.

Downstream error statuses are returned for host handling. No automatic auth retry, rejection, revocation or business-write replay occurs. A timeout or transport failure can leave a business write's outcome unknown; reconcile the original domain operation before deciding what to do next. Safe `IdentityException` codes expose no remote body, token or exception cause.

Every token/reject/revoke/request path checks the outer `ExecutionPolicy` before cache/HTTP effects. Token publication and downstream attachment recheck it, as do lock callbacks. Constructing a service through another named consumer graph does not replace the ambient request's active/pending delegation boundary. Worker access does not propagate ambient subject authority into outbound calls or jobs.

Using `token()` for manual attachment transfers destination/header/cookie/redirect/timeout/response and replay responsibilities to the host. Never serialize tokens into browser props, job payloads, public JSON or logs. The inbound `ResourceVerifier` remains a separate credential/authority plane.

## Qualification boundary

The isolated Services tests exercise real token-manager/cache code with fake external HTTP. They cover independently bound targets, credential/issuer/scope isolation, encrypted corruption/swaps, generation-safe delayed eviction, index-first publication failures and recovery, expiry, fixed destinations and header/body/response bounds, outages, cross-graph delegated refusal and three concurrent PHP processes using Laravel's file cache. They do not qualify a production Redis/database adapter, genuine HTTPS downstream interoperability or independent resource verification. Those remain coordinated integration/production checks.
