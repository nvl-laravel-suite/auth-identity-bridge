# Native user synchronization

This extension adds webhook-driven, versioned user synchronization. Check the current verification record for completed invocations; older native integration results do not qualify a new source change.

Configure the following `users` and `sync` fragments inside `identity.consumers.default`, retaining every other required field from the published canonical configuration. Use explicit `Identity::consumer(name)` graphs outside a selected browser request.

## Enable one receiving client

In Identity's **Consumer access → Client policy**, explicitly enable **Background user synchronization** (`users.sync`) on the confidential interactive client. This capability permits app-scoped synchronization reads. The separate `users.sync.metadata` capability additionally permits backend governance metadata; it requires `users.sync`. The separate `users.import` migration capability also requires `users.sync` and explicit confidential-client enablement. It grants no user-management writes, credential changes, role assignment or impersonation authority.

The package uses that client's configured Basic credentials at two fixed HTTPS endpoints:

| Endpoint                                   | JSON input                                                                                      |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| `POST /api/consumer-sync/v1/profiles.read` | `{ "subjects": ["subject-id"] }`, one to 100 distinct subjects                                  |
| `POST /api/consumer-sync/v1/profiles.list` | `{ "limit": 100, "cursor": "opaque-nextCursor-from-previous-response" }`; omit cursor initially |

Sync/import responses and the ordinary `/api/consumer/v1/` JSON result plane each have a fixed 16 MiB transport ceiling for bounded rich-profile batches and directory pages. Generic HTTP, OIDC and other endpoint response limits remain unchanged. Every read/list response binds `platform-consumer-sync.v1`, issuer, application, client and current policy version. Each record contains subject, monotonic application/subject version, lifecycle state and current profile. Required profile fields include name, email, email verification, HTTPS picture URL or null, locale, IANA timezone, account type (`individual` or `company`), phone, organization name, position, biography, real calendar date of birth, gender, ISO country, safe HTTPS social links and the server-computed `profileCompleted` flag. Optional facts have explicit null values. Backend `adminNotes`, `tags` and `lastLoginAt` are always present; without `users.sync.metadata` their values are null, an empty list and null. Last login IP never crosses this contract. Self-service, UserInfo and OIDC claims do not expose governance metadata. Unknown/out-of-scope IDs are omitted; omission is never a deletion signal. Previously enrolled revoked/deleted identities receive explicit tombstones without new profile data.

The provider emits case-sensitive timezone IDs from `Intl.supportedValuesOf('timeZone')` plus `UTC`. PHP validates against `DateTimeZone::ALL_WITH_BC`, preserving valid ICU/TZDB aliases such as `Asia/Calcutta` and `Europe/Kiev`; offsets and free-form/case-changed timezone strings are rejected. Recheck runtime compatibility when upgrading ICU or PHP timezone data.

The ordinary `ConsumerClient` profile read/update and directory/access response validators require the same shared profile fields while excluding governance metadata. Partial self-profile updates forward only supplied fields; explicit null clears a nullable field, and omitted fields remain unchanged at the provider. Account type and computed completion are readable shared facts; account type remains administrator/onboarding owned.

This projection enrolls app-associated people. New organization-contact/non-person identities are outside its scope; a previously enrolled person who becomes ineligible receives a revoked tombstone. Ordinary human-authorized directory/management APIs retain their separate scope.

## Native model mapping

Enable synchronization explicitly in the host configuration. Provisioning missing users is a separate opt-in:

```php
// Fragment inside consumers.default; keep the rest of the published definition.
'users' => [
    'model' => App\Models\User::class,
    'factory' => IdentityPlatform\Laravel\Users\EloquentNativeUserFactory::class,
    'resolver' => IdentityPlatform\Laravel\Users\EloquentIdentityUserResolver::class,
    'mapper' => IdentityPlatform\Laravel\Users\EloquentNativeUserMapper::class,
    'identity_projection_writer' => 'default',
    'fields' => [
        'name' => 'name',
        'email' => 'email',
        'email_verified_at' => 'email_verified_at',
        'picture' => 'avatar_url',
        'state' => 'identity_status',
        'locale' => 'locale',
        'timezone' => 'timezone',
        'phone' => 'phone',
        'organizationName' => 'organization_name',
    ],
],
'sync' => ['enabled' => true, 'provision_missing' => true, 'import_enabled' => false],
```

Create the mapped columns in the host's own Eloquent migrations. The package does not alter an existing application's user schema. A custom factory handles required host fields; the injectable native mapper supports other schemas. The reference app supplies its own avatar/status columns.

Only explicitly mapped provider-owned fields are updated. Supported source keys additionally include `accountType`, `position`, `bio`, `dateOfBirth`, `gender`, `country`, `socialLinks`, `profileCompleted`, `adminNotes`, `tags` and `lastLoginAt`. Configure Eloquent array/JSON casts for mapped `socialLinks` and `tags`. An explicit null clears its mapped nullable column, and metadata redaction clears previously mapped governance values on a newer snapshot. Unmapped display names, biographies and preferences remain host-owned, as do role tables and domain records. Metadata and synchronized profiles never authorize an operation. Native users are associated by issuer/subject/consumer binding, never by matching email. A duplicate email constraint is a reported conflict; no existing account is silently linked.

Active batch projection holds one binding-policy lock for the complete native transaction. Inactive acceptance first commits its binding/version/digest/lifecycle and session retirement without looking up native rows; native projection follows in a separate transaction. Native projection locks existing native rows before shared projections and accepted state. Standalone snapshot application acquires its own binding lock. Snapshot application uses version/digest checks. A lower version cannot regress fields or revive access; an equal version with different facts is a conflict. Older policy responses cannot overwrite a newer binding policy. After accepting versioned data, unversioned login/delegation facts cannot replace it. `ProfileSynchronized` remains an after-commit application hook, not permission authority.

Avatar values are HTTPS URLs, validated before mapping/rendering; no server-side image download is performed. Null clears the provider-owned avatar. Application avatar overrides remain separate host fields.

## Typed mapping and ownership

`users.fields` is the single mapping schema. A string remains the direct form; an entry may instead be `{column, transform, cast, options}`. Optional entries default to a null transform/cast and empty options. Transformer class strings implement `NativeValueTransform`, have no required constructor arguments, and validate their options during consumer registry construction. The bundled transforms are `LifecycleBoolean`, `NullableDate`, `NullableTimestamp`, `ArrayValue`, `EnumValue` and `SafeAvatar` in `IdentityPlatform\Laravel\Users\Transforms`.

```php
'fields' => [
    'name' => 'display_name',
    'email' => 'contact_email',
    'state' => [
        'column' => 'enabled',
        'transform' => IdentityPlatform\Laravel\Users\Transforms\LifecycleBoolean::class,
        'cast' => 'boolean',
    ],
    'dateOfBirth' => [
        'column' => 'birth_date',
        'transform' => IdentityPlatform\Laravel\Users\Transforms\NullableDate::class,
        'cast' => 'immutable_date',
    ],
    'tags' => ['column' => 'identity_tags', 'cast' => 'array'],
],
'local_fields' => ['display_override', 'business_reference'],
'readonly_fields' => ['computed_label'],
'protected_fields' => ['custom_credential'],
```

Actual primary/auth identifier/password/remember-token columns, foreign keys, generated columns, read-only accessors, security/role/permission fields and declared host-owned destinations cannot be mapped. Mandatory authority reservations include singular role/permission and privilege/admin, MFA/two-factor, credential/security and authentication/authorization field families, including conventional camelCase variants. Host ownership declarations only add restrictions; empty declarations cannot override reserved destinations. Conventional active/enabled/disabled/locked and account-status destinations require the canonical `state` source and an unshared native destination; an explicit `LifecycleBoolean` mapping can drive an unshared boolean flag. Other business-specific authority names must still be declared protected by the host. `NativeMappingDefinition::preflight($model)` performs read-only host schema checks for worker/import startup; mapping also invokes it before assigning fields. Use native Eloquent casts on the model for consistent later reads. Inline `cast` controls assignment; supported casts are scalar, array/JSON, date/datetime, immutable date/datetime and backed enum classes. `EnumValue` takes `options => ['enum' => HostEnum::class]`. The default factory uses these same mappings, so custom names and UUID model keys do not require package table changes. A custom factory must insert a new configured native model during its invocation; returning an existing row is refused, including an object retaining `wasRecentlyCreated`. The insertion observer is scoped to the synchronous factory call and restores the model event dispatcher in `finally`; coroutine execution is not qualified.

Optional `users.lifecycle_policy` defaults to `RetainedNativeLifecycle`; a registered `NativeLifecyclePolicy` can narrow provisioning or refuse mapping. The default retains rows and never restores soft-deleted records. `protected_fields`, `local_fields` and `readonly_fields` default to empty lists. Verified JIT omission preserves previously accepted binding facts; explicit null clears a mapped nullable value. Policy-redacted metadata remains explicit null/empty in the unchanged wire contract. Tombstones clear mapped governance metadata while retaining required host identity/display fields.

Every browser consumer declares `users.identity_projection_writer` for its issuer, including unmapped consumers and consumers using separate native tables. `identity_projection_epoch` defaults to 1 and must match across that issuer. The physical common `IdentityUser` writer is fenced in package-owned `identity_projection_owners`; other consumers retain their own accepted or verified JIT facts in their binding state. `UserProjectionRepository::find/present` and native mapping use those facts. Common rows contain no governance metadata. Application versions are never compared across bindings.

Sharing a native row is disabled by default. Configure the same `users.native_group => ['name' => 'people', 'writer' => 'receiving-consumer', 'epoch' => 1]` on each approved participant. The group writer must be registered, use the same issuer and physical native table, and may differ from the common projection writer. Only that writer provisions or maps the shared native row. Group mappings forbid lifecycle `state` and governance metadata: one application's revocation cannot drive a global person-active flag or disclose its metadata to another consumer.

For a second participant, fetch and apply its current verified `UserSnapshot`, then explicitly call its graph's `NativeUserAssociation::associate($snapshot, $trustedSourceBinding, $exactNativeId)`. The service requires an exact current active accepted version/digest/policy matching the locked binding’s current policy, a trusted existing same-issuer/subject/native-ID source link and the approved group. It refuses arbitrary IDs, email acquisition, foreign ownership and reassignment. A typed `UserImportResult` plus supplied source/native pairs provides the separate bootstrap proof path. Physical ownership keys use connection/table/primary key, so another model class cannot bypass ownership. Association marks native work pending; refetch/apply completes the writer-governed projection.

Changing a writer or epoch in configuration never transfers ownership. Writes and retries refuse with `identity_projection_owner_fenced`. `ProjectionOwnership::transfer($ownerId, $expectedBinding, $expectedEpoch)` locks and checks the recorded owner and explicitly refuses with `identity_projection_handoff_required`. There is no automated handoff in this release. A future handoff must stop/drain old work, fence the old epoch, reconcile visibility-owned fields, install the new owner and fetch fresh authorized state before projecting. Do not edit owner rows to bypass this refusal.

## Accepted state and projection retry

The additive package migration `2026_11_01_000200_add_identity_native_projection_state` adds `native_version`, `native_status`, `native_error`, binding-only `jit_profile` and physical projection ownership storage. It changes no host table and leaves existing accepted lifecycle/association data intact. Existing accepted states begin native-pending and require authorized reconciliation.

`version`, `digest`, `state` and `profile` represent accepted binding facts. `native_version` records the last applied native version; `native_status` is `pending` or `applied`, with only the safe `native_projection_failed` diagnostic persisted. A missing/soft-deleted row, transform error or ownership fence cannot undo committed inactive acceptance or session retirement. A fresh same-version/digest proof refreshes accepted policy evidence under the binding/state locks without changing accepted facts or native version, even if its pending native-only retry fails. Advancing policy through a different subject invalidates older association proofs until that subject is freshly verified. The same version/digest retries pending projection; an equal conflicting digest fails, stale input cannot regress, and every projection rechecks current accepted state and owner under locks. Active native creation/linking/mapping remains atomic. A failed native batch rolls back its native writes while preserving inactive acceptance committed beforehand.

`apply()`/`applyBatch()` retain their signatures and add the `native_pending` outcome. `UserSyncManager::process()` raises `user_sync_native_pending` without completing the work generation. Reconciliation counts durable `nativePending` independently of page results and refuses convergence while any accepted projection remains unresolved. Work rows reuse the existing refetch generations, retry schedule and cursors. Retried mapping never restores retired sessions.

## Explicit consumer bootstrap

Bootstrap is an application-owned migration operation. The package does not enable it, schedule a job, run migrations or select native records automatically. Apply the package migration for `identity_user_import_links` through the host's normal deployment process; it adds only package-owned association storage and does not alter the native user/password schema. Enable `sync.enabled` and `sync.import_enabled` locally and enable `users.sync` plus `users.import` on the confidential receiving client for the migration window.

```php
use IdentityPlatform\Laravel\Facades\Identity;
use IdentityPlatform\Laravel\Sync\UserImportBootstrap;
use IdentityPlatform\Laravel\Sync\UserImportClient;

$consumer = Identity::consumer('default');

// Obtain this native record through the host's explicit export/selection policy.
$result = $consumer->make(UserImportClient::class)->import([
    [
        'sourceUserId' => 'native-42',
        'name' => $nativeUser->name,
        'email' => $nativeUser->email,
        'emailVerified' => $nativeUser->email_verified_at !== null,
        'roleKeys' => ['reader'], // Existing application roles within this client's ceiling.
    ],
]);

$outcomes = $consumer->make(UserImportBootstrap::class)->associate($result, [
    ['sourceUserId' => 'native-42', 'nativeUserId' => $nativeUser->getKey()],
]);
```

`UserImportClient::import(array $users): UserImportResult` sends `{users: [...]}` to `POST /api/consumer-sync/v1/profiles.import` using only the configured receiving client's Basic credentials. Each batch has one to 100 distinct source IDs and distinct emails. Name, email and boolean email verification are required; rich profile fields, active state, existing `roleKeys`, and a supported bounded `passwordHash` are optional. `profileCompleted` is computed by the provider and cannot be supplied. Metadata input requires `users.sync.metadata`. Handle credential hashes privately in a controlled migration process; do not put them in logs, queue payloads or local profile rows. Unsupported/excessive-cost hashes are rejected by the provider.

The typed result validates `platform-consumer-sync-import.v1`, exact issuer/application/client, positive policy version, and exactly one distinct returned source and subject per requested source. Each `UserImportMapping` exposes `sourceUserId` and its validated `UserSnapshot` as `snapshot`. Subjects are generated by the provider; a source UUID is never a global subject. A supplied email never links an existing provider identity. An unlinked canonical-email collision rejects the provider batch. Repeating the same source binding returns its current identity without overwriting later credentials, profile or access changes.

`UserImportBootstrap::associate(UserImportResult $result, array $associations): array` requires one explicit `{sourceUserId, nativeUserId}` pair per result mapping. It loads only those exact native primary keys on the same consumer connection, never searches by email, and atomically persists source/subject/native associations with current snapshots. Source identity is pinned to the configured issuer/client/application/origin/cookie binding; replay cannot reassign a source, subject or native owner. The supplied native ID must match exactly. An existing native association conflict or missing ID rolls back the native association batch. Already accepted inactive security facts and session retirement remain committed. Public inactive apply/import refuses a caller-owned outer transaction with `user_sync_outer_transaction_unsupported`; savepoints cannot provide durable independent acceptance. Repeating a valid association is idempotent and retains newer profile/lifecycle data; a delayed policy response is rejected. Outcomes (`applied`, `unchanged`, `stale`) follow result mapping order. Bootstrap creates no sessions and grants no local permissions.

Provider import and local bootstrap are separate service transactions. If local association fails after provider import, correct the explicit native mapping and repeat the same source IDs; do not create replacement sources or merge by email. Remove `users.import` and set `sync.import_enabled` to false after migration while leaving normal synchronization enabled as needed.

## Webhooks and workers

Configure the application subscription to send supported profile and entitlement invalidations to the consumer's `POST /identity/events` endpoint. Store the generated subscription secret as `IDENTITY_EVENT_SECRET`; never expose it to browser code. Keep ordinary CSRF protections on browser routes; the callback route authenticates exact signed bytes instead of browser cookies.

The existing six-field event envelope contains no profile patch. HMAC, application/subject binding, timestamp validation and durable duplicate receipts are checked before creating local sync work. Provider delivery persists attempts and supports retries/dead-letter replay. Local receipt and pending work commit together; after-commit jobs carry only a local request-row reference, load its binding before constructing their consumer graph and perform a fresh authorized refetch. Unknown/removed bindings raise a sanitized `unknown_consumer_binding` diagnostic rather than silently completing another consumer's work.

Run the normal provider delivery worker and Laravel queue worker under the deployment's process supervisor. For local Laravel operation:

```sh
herd php artisan queue:work --tries=10
herd php artisan schedule:work
```

Herd already serves the PHP site; these commands run workers, not another web server. For production, use Laravel's normal queue supervisor and scheduler invocation. The reference app schedules bounded reconciliation every minute with overlap protection.

Rate limits and temporary transport failures preserve the current local profile. Pending work records a retry state; jobs honor bounded retry delays. A lost after-commit dispatch does not lose the durable request, and reconciliation recovers it.

## Lifecycle and reconciliation

States are `active`, `pending`, `suspended`, `revoked` and `deleted`. Only active, authorized identities can authenticate. Inactive snapshots retire this binding's local sessions and deny native resolution. Reactivation requires a newer valid snapshot and a new ordinary sign-in; synchronization itself creates no browser session or permissions.

Tombstones preserve native associations and domain data. The default mapper retains required native name/email columns while clearing mapped avatar/verification fields and recording inactive status. This is access retirement, not an application data-deletion policy.

Run a bounded reconciliation page manually:

```sh
php artisan identity:users-reconcile --consumer=default --limit=100
```

The result reports provider/known-user progress and continuation cursors. Provider cursors are opaque, authenticated values up to 4,096 characters; store them unchanged, rather than treating them as subject IDs. Cursors persist across invocations and advance only after successful page application. An explicit expired/policy-invalid cursor starts a fresh bounded scan; unrelated refusals and temporary failures do not reset progress. Repeat or schedule bounded calls until `completed` is true; null cursors alone do not prove completion, and a single page is not a global snapshot. Each cycle also checks known users to recover missed revocation/deletion events. Partial failure is reported and preserves retryable progress. Approved people may be provisioned before their first Laravel login only when `provision_missing` is enabled.

Reconciliation persists independent exhaustion for the directory and known-subject scans: whichever scan finishes first waits while the other advances. Traversal coverage is bound to the captured binding generation and accepted policy version. A newer binding invalidation or accepted policy restarts both scans so eligible records before an old cursor are revisited. A policy change during a traversal returns incomplete and requires a fresh bounded cycle. A monotonic progress revision and compare-and-swap checks reject stale publication even if cursors later return to the same values. Completion still requires zero pending subject/binding/native work and zero unresolved imports; omitted subjects retain durable retry work. The public reconciliation call remains bounded to one known-subject batch and one directory page, with the existing bounded invalid-cursor retry.

Apply the additive package migration `2026_11_02_000000_add_identity_user_sync_exhaustion` through Laravel's normal migration runner before using this package source with an existing consumer store. It adds independent exhaustion, traversal generation/policy and progress revision fields to package-owned synchronization state. The migration leaves existing cursors, accepted snapshots, work generations, native users, associations, import checkpoints and foreign keys intact; it does not alter the host's native user schema. The first normal reconciliation restarts unknown inherited scan coverage under the existing lease and compare-and-swap fences. That fresh bounded runtime scan preserves and reuses accepted records idempotently; it is not a store or ledger reset.

An omitted known request is isolated: its work/error remains pending, while returned profiles and subsequent directory pages continue. Results include `missing`, `pending`, `nativePending` and `completed`; unresolved work prevents a completed claim, and a page with missing records exits nonzero after emitting its JSON result. Resolve its eligibility/source issue rather than deleting local users or silently linking accounts. One out-of-scope identity does not block unrelated synchronization.

## Herd delivery without weakening production

Supply `LOCAL_IDENTITY_EVENT_URL=https://tss-auth-test.test/identity/events` only to development/test provider and worker processes. Do not put it in a universal production environment. Production refuses this override. The development policy allows one exact callback, verifies that every resolved address is loopback, pins the socket and retains the original hostname/SNI and certificate verification. Redirects and arbitrary private-network destinations remain forbidden.

Use the trusted system CA store for Node (`NODE_USE_SYSTEM_CA=1`); do not disable TLS verification or HTTP/2. Production delivery continues to require public HTTPS destinations.

From the provider project, start development and delivery in separate terminals:

```sh
NODE_USE_SYSTEM_CA=1 LOCAL_IDENTITY_EVENT_URL=https://tss-auth-test.test/identity/events npm run dev
NODE_USE_SYSTEM_CA=1 LOCAL_IDENTITY_EVENT_URL=https://tss-auth-test.test/identity/events npm run worker:delivery
```

The Laravel queue/scheduler commands above run from the sample directory. Run all worker processes under the deployment's normal supervisor for ongoing operation; the acceptance tests use bounded worker invocations.

True concurrent PostgreSQL host locking, production shared-lock leases, distributed load, external delivery/outage behavior and retention remain separate qualification gates. Local SQLite/Herd acceptance does not establish them.
