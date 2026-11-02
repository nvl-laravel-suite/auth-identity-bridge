# Identity bridge notifications

The bridge publishes local Laravel notifications for authentication lifecycle and profile convergence. The machine-readable [event catalog](../resources/event-catalog.json) records the existing classes and payloads. Catalog `schema_version: 1` versions the catalog format; these retained notification classes have no `schemaVersion` field or method and do not implement the optional NVL Core domain-event contract.

## Immutable lifecycle notifications

These four `IdentityPlatform\Laravel\Events` classes are readonly payloads. Their public constructor fields are their complete payloads:

| Class | Fields | Producer transition |
| --- | --- | --- |
| `AuthenticatedSessionEstablished` | `consumer: string`, `actorSubject: string`, `contextVersion: int` | A verified browser session is established. |
| `ContextSelected` | `consumer: string`, `actorSubject: string`, `organizationId: ?string`, `roleId: ?string`, `contextVersion: int` | A session's organization/role context changes. |
| `DelegationStateChanged` | `consumer: string`, `actorSubject: string`, `effectiveSubject: ?string`, `status: string`, `contextVersion: int`, `expiresAt: ?string` | Delegation becomes `pending`, `active` or `stopped`. |
| `LocalSessionEnded` | `consumer: string`, `actorSubject: string`, `contextVersion: int` | The owned local session ends, including local directory and delegation teardown paths. |

`Events\LifecycleNotifications` is the internal dispatcher, not a notification. It captures the graph's Laravel dispatcher and payload, then registers a callback on the supplied model connection's outer commit. With no active transaction it dispatches immediately. A rollback discards the corresponding pending callback. Listener exceptions are caught so optional observation cannot undo or replay the committed authentication/security transition.

These notifications contain identifiers and transition facts. They omit credentials, browser tokens, session/vault identifiers, raw decisions and private reasons. Their `contextVersion` describes the observed transition; it is not current authorization, a write fence or permission to impersonate. An actor remains the operator when `effectiveSubject` describes a delegated subject.

## Profile convergence hook

`IdentityPlatform\Laravel\Sync\ProfileSynchronized` is the established application hook with `user: IdentityPlatform\Laravel\Models\IdentityUser` and `created: bool`. It uses Laravel `Dispatchable`, `SerializesModels` and `ShouldDispatchAfterCommit`. JIT synchronization emits it after verified UserInfo projection; versioned native application emits it after the projection connection commits. An already applied unchanged or stale snapshot returns without a new application notification. JIT observations may repeat for later authenticated refreshes.

This hook carries a projection model and differs from the scalar lifecycle payloads. Treat profile attributes as personal data. Queued model serialization/restoration follows Laravel's model behavior and can observe later persisted state; it is not an immutable authorization snapshot. Listener failures follow normal Laravel dispatch/queue behavior rather than the lifecycle dispatcher's best-effort containment. Keep host side effects idempotent and use fresh authorized reads for decisions.

## Host listeners and delivery

Register listeners or `Event::fake([...])` with the exact notification class. The bridge provides no compatibility aliases, durable notification outbox, retry ledger or exactly-once delivery guarantee. A process exit after database commit can lose local callbacks; separate transitions and requests can produce multiple observations. Hosts own listener retry, privacy, queue and transport policy. Keep listener payloads out of public feeds unless the host deliberately constructs an authorized safe representation.

Signed provider callbacks are a separate inbound protocol documented in [user synchronization](user-synchronization.md). They invalidate local knowledge and schedule authorized current reads; the local notifications above neither replace signed verification nor grant account association or permission authority.
