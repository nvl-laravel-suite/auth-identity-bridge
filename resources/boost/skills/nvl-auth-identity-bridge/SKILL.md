---
name: nvl-auth-identity-bridge
description: Integrate or troubleshoot a Laravel app using nvl/auth-identity-bridge for Identity Platform OIDC and redirects, native user data, self-service or managed profile updates, two-way synchronization, controlled imports, authorization, scoped impersonation, signed callbacks and service targets.
---

# NVL Auth Identity Bridge

Build on the existing bridge owners. Keep business models, policies and presentation in the consuming app. Do not introduce a second authentication system, a generic integration framework or business-specific package code.

Use [installation](references/installation.md) for publication and migration ownership, [API](references/api.md) for exact public declarations and [usage](references/usage.md) to select the current integration owner.

## Establish context first

1. Read the host's instructions and installed bridge version/source. Locate it with `composer show nvl/auth-identity-bridge --path`; in the NVL suite it is `packages/nvl/auth-identity-bridge`. PHP APIs use `IdentityPlatform\Laravel`, independently of the Composer name. No `nvl/core` or `nvl/auth` dependency is required.
2. Identify the view/operation's purpose, displayed facts, field ownership, actor, effective subject, trusted consumer, organization/role and native resource. Record those briefly in the implementation notes. Distinguish browser authority, synchronization credentials and service credentials.
3. Read the relevant installed-package contract below and its current source/caller before editing. Read [workflow recipes](references/workflows.md) for the corresponding integration path. Do not copy configuration or proof-bearing URLs from another app.

| Work | Read in the installed package | Existing owner |
| --- | --- | --- |
| Installation, named consumers, native mapping | `README.md`, `config/identity.php` | `Providers\AuthIdentityBridgeServiceProvider`, `Support\ConsumerRegistry`, `Users\NativeUserMapper` |
| Login, selection, return paths, logout, Blade/JSON/Inertia/Livewire | `HEADLESS-LIFECYCLE.md` | `Auth\BrowserLifecycle`, `Auth\PostContextDestinationResolver`, `Auth\BrowserDestination` |
| Self profile, directory, access, roles, invitations, MFA | `docs/profile-and-user-bootstrap.md`, `docs/reusable-integration-contracts.md`, `Consumer\ConsumerClient` source | `Consumer\ConsumerClient::call` allowlisted operations |
| Governed target profile/metadata writes and recovery | `CONSUMER-MANAGEMENT.md` | `Consumer\ManagedOperations`, `Consumer\CommandJournal` |
| Native synchronization and callbacks | `docs/user-synchronization.md` | `Sync\UserSyncManager`, `Sync\UserSnapshotRepository` |
| Import existing native users | `IMPORTING.md` | `Sync\UserImportSourceRegistry`, `Sync\ImportRunner` |
| Gate policies, local writes, scoped impersonation | `AUTHORIZATION.md`, `docs/reusable-integration-contracts.md` | `Authorization\IdentityAccess`, `Authorization\OrdinaryActionRunner`, `Delegation\DelegatedActionRunner` |
| Remembered resource filter | `APPLICATION-CONTEXT.md` | `ApplicationContext\ApplicationContextManager`, `ApplicationContext\ApplicationContextRegistry` |
| Machine-to-machine calls | `SERVICE-TARGETS.md` | `Services\ServiceTokenManager` |

## Integration rules

- Installation is disabled by default. Publish/configure the bridge, then explicitly enable `nvl-auth-identity-bridge.enabled`. Configure reviewed migrations, native field mappings and a supported shared lock store before admitting traffic. Preserve applied migration names and host data.
- Resolve a trusted named graph with `Identity::consumer($trustedName, $request)->make(...)`; use `Identity::browser()` only on an admitted browser request. Jobs persist a safe local reference and reopen its exact binding. Never serialize the graph, browser tokens or session authority.
- Two-way data flow means authorized app-to-provider operations followed by versioned provider-to-native convergence. Native rows, profile facts, cached projections and readable/writable-field hints grant no permissions. Never associate accounts by email or write to the provider database.
- Preserve exact issuer/client/application/subject/SID/audience bindings, independent consumer cookies, supported locks, PKCE/nonce, one-use intents, exact Origin/CSRF, live session deadlines, selected role and final context/token fences. Do not disable middleware to repair an integration.
- Keep ordinary actor and delegated effective subject distinct. Gate/UI checks cannot replace write admission, locked native resource policies or the existing runners' final fences. Application resource context is a filter, not organization/role selection or delegation.
- Use typed managed results and their safe error codes. Keep full command references in private host state; expose only safe outcome fields under an opaque host draft identifier. Preserve omission versus explicit null, original idempotency reference, current target revision, and committed-but-refresh-pending truth. Never recover an ambiguous write using a new key or map a managed read/receipt into native users.
- Signed callbacks invalidate; current authorized snapshot reads obtain facts. Imports require both creation paths paused, drained old workers, a trusted source and same-run recovery. Use the existing import/reconcile commands rather than a second importer.
- Keep credentials, tokens, session/vault identifiers, private reasons, raw provider errors and proof-bearing links out of UI props, logs, jobs, skill examples and reports. Use the safe presentation DTO for browser state.

## Verify and stop

Use focused existing tests for the changed boundary, then the package gate. In the suite: `herd php tools/run-package-tests.php auth-identity-bridge --concurrency=1`. In a standalone development checkout: `composer --no-plugins verify`. For the native sample run `herd php artisan test --compact` without private overrides. Run a live journey only when that changed integration needs it, with its owned synthetic fixture.

Herd already serves PHP. Preserve HTTPS/HTTP2, human accounts and stores; inspect process ownership before any lifecycle action. Never start another PHP server or reset a store for qualification. Report exact commands, counts, failures/skips and unverified live/deployment boundaries. Package tests alone do not establish provider, database-engine, browser or production acceptance. Stop after the affected acceptance criteria pass.
