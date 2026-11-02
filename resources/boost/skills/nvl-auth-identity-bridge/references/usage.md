# Use the Identity bridge

Keep the consumer application's models, resource policies, routes and presentation in the host. The installed `nvl/auth-identity-bridge` package supplies the existing Identity Platform integration owners under `IdentityPlatform\Laravel`; it has no runtime dependency on `nvl/core` or `nvl/auth`.

Read [installation](installation.md) for the discovered provider, configuration publication and migration ownership, and [API](api.md) to confirm the exact public declarations. Read [workflow recipes](workflows.md) for concrete browser, self-service, managed-command, synchronization, import and delegated-write paths. Locate the package with `composer show nvl/auth-identity-bridge --path`; the named contract files below are relative to that installed package, not the published skill folder.

## Select the existing owner

| Operation | Installed contract | Owner |
| --- | --- | --- |
| Browser login, callback, selection, landing and logout | `HEADLESS-LIFECYCLE.md` | `Auth\BrowserLifecycle`, `Auth\PostContextDestinationResolver` |
| Self profile, directory, roles, invitations and step-up | `docs/reusable-integration-contracts.md` | `Consumer\ConsumerClient::call` |
| Governed target profile or metadata update and recovery | `CONSUMER-MANAGEMENT.md` | `Consumer\ManagedOperations`, `Consumer\CommandJournal` |
| Signed invalidation and versioned native convergence | `docs/user-synchronization.md` | `Sync\UserSyncManager`, `Sync\UserSnapshotRepository` |
| Existing-user bootstrap | `IMPORTING.md` | `Sync\UserImportSourceRegistry`, `Sync\ImportRunner` |
| Current authority, local writes and scoped impersonation | `AUTHORIZATION.md` | `Authorization\IdentityAccess`, `Authorization\OrdinaryActionRunner`, `Delegation\DelegatedActionRunner` |
| Remembered native resource filter | `APPLICATION-CONTEXT.md` | `ApplicationContext\ApplicationContextManager` |
| Fixed worker credentials and downstream calls | `SERVICE-TARGETS.md` | `Services\ServiceTokenManager`, returned `Services\ServiceTokenClient` |
| Local lifecycle and profile notifications | `docs/events.md` | Immutable lifecycle DTOs and `Sync\ProfileSynchronized` |

## Bind each operation explicitly

```php
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Facades\Identity;

// The host selects this trusted name for the admitted route.
$graph = Identity::consumer('workspace', $request);
$client = $graph->make(ConsumerClient::class);
$profile = $client->call($request, 'profile.read');
```

The graph and retained services keep their exact consumer binding. Do not serialize the graph, browser tokens or session authority into jobs. Jobs persist a safe local reference and reopen its original binding. Different browsers and workers retain independent credential and session planes.

Reserve the package's established `identity` configuration key, auth guard driver and view namespace, `identity.*` middleware aliases and `identity-config` legacy publication tag. Named consumer guard names and route paths come from the trusted consumer configuration. The standalone provider registers these retained names directly; it does not depend on Core's namespaced-resource collision helper. Check host conflicts before enabling it.

Use live provider decisions for authority and locked host policies for native resources. Profiles, cached projections, readable/writable-field hints and lifecycle notifications never grant permission. Keep the actor and delegated effective subject distinct. Preserve the existing admission middleware and the ordinary/delegated runners' final fences.

Managed commands preserve omitted fields versus explicit null, the displayed target revision, original idempotency reference and current local context. Retain the full reference in private host state and expose safe outcomes under an opaque draft identifier. Unknown/pending outcomes require original-command recovery; a committed command with native refresh pending remains committed. Governed reads and command receipts do not feed native mapping. Signed callbacks invalidate; an authorized current snapshot supplies facts.

Existing-user imports require paused creation paths, drained old workers, a trusted import source and recovery of the same run. Do not add email-based linking, a second importer, native-save echo observers or direct provider database access. Outbound workers use configured fixed targets and cannot borrow browser or delegated authority.

## Verify the changed boundary

Use focused existing package and consumer tests. In the suite run `herd php tools/run-package-tests.php auth-identity-bridge --concurrency=1`; in a standalone development checkout run `composer --no-plugins verify`. Default SQLite tests and the separately opted-in PostgreSQL suite have different qualification boundaries. Live browser/provider, cache, database-engine and deployment checks require their own owned fixtures and evidence.

Keep credentials, tokens, session/vault identifiers, private reasons, raw provider errors and proof-bearing URLs out of browser props, logs, reports and jobs. Preserve human accounts, active stores, HTTPS and existing authorization boundaries. Stop after the changed acceptance criteria pass and report exact verification and remaining live boundaries.
