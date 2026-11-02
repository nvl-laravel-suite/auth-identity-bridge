# Shared profiles and explicit user bootstrap

Identity owns shared contact, work, preference and optional demographic/social facts. Applications retain domain data and authorization. `organizationName` describes work; it does not create an organization membership or grant. Account type is administrator/onboarding owned; a governed other-user consumer editor may write it only through explicit managed field policy, never self-service. Completion is computed from name, time zone and phone, with organization name additionally required for company accounts; optional demographics do not gate completion.

The account and platform People editor share a typed Themelia form: searchable country/time-zone choices, retained optional sections, structured social links and administrator-only tag/note controls. ESLint prohibits native browser dialogs. React confirmations use Themelia overlays; the independent Blade sample has an accessible native HTML confirmation preserving bound form submission. See the feature verification record for exact invocation counts and scope.

## Visibility and validation

Self-service and ordinary shared profile responses exclude operator notes, tags and login facts. Governed other-user profile and metadata management use separate explicit capabilities and field policies below. Existing OIDC/UserInfo claims remain narrow. Platform administrators edit notes/tags and inspect last sign-in facts. Login IP stays administration-only and is never synchronized. None of these values grant permissions.

`users.sync` returns app-associated versioned profiles. Additional `users.sync.metadata` opt-in exposes `adminNotes`, `tags` and `lastLoginAt` to that confidential receiving client. Without it they are null, empty, null. Removing access transactionally advances retained snapshot versions and emits invalidations, allowing consumers to clear explicitly mapped columns. Existing policy/digest/lifecycle checks remain intact.

Dates are real non-future `YYYY-MM-DD` values; countries use ISO alpha-2; time zones use the canonical runtime IANA list plus UTC. HTTPS social/picture URLs have no credentials, normalize IDNA/percent encoding and obey canonical length limits. Partial updates preserve omitted fields; explicit nulls clear optional values.

## Governed consumer profile management

Keep shared identity facts separate from native display overrides, app preferences, business data and permissions. The current consumer contract adds `users.profile.manage` and `users.metadata.manage` independently of self-profile and directory access. Current ordinary actor permission **and** matching client ceiling, source-bound recent MFA, eligible active person target and protected-target rules apply even to reads. No email/classification/security editing is added. Metadata management additionally requires `users.sync` and `users.sync.metadata`.

Explicit policy lists determine readable/writable fields. Both write groups require `managedProfileGlobalEffectsAcknowledged`; writes affect the person's shared facts across applications. `profileCompleted` is read-only, `accountType` needs explicit approved write policy and metadata writes contain only `adminNotes`/`tags`, never login facts. Managed reads are exactly `{id,version,fields,writableFields}`; required sorted canonical `writableFields` is a current UI hint, never a grant. It may be empty. Missing/older shapes are refused.

Use [PHP typed helpers/private journal](../CONSUMER-MANAGEMENT.md) or Node `createConsumerManagementClient` from `@identity/client/server`. Updates retain positive target revision, reason and original idempotency key; local context version is a separate fence. Unknown commit outcomes recover under the original ordinary source/reference, never by changing actor/context or issuing replacement keys. Confirmed commit remains committed through context/refresh failures. Only a current authorized versioned sync snapshot updates native mappings; managed reads and receipts are not patches. See the generic consumer checklist.

## Import contract

Enable `users.import` on a confidential receiving client with `users.sync` only while migrating. New-source governance input also requires `users.sync.metadata`. This explicit migration capability does not give general existing-user management authority.

`POST /api/consumer-sync/v1/profiles.import` uses the receiving client's confidential authentication and `{ "users": [...] }`: at most 100 distinct source IDs/canonical emails, within fixed 16 MiB request/response bounds. Read/list inputs retain their 64 KiB bound. A minimum entry is:

```json
{
  "sourceUserId": "source-person-42",
  "name": "Example Person",
  "email": "person@example.test",
  "emailVerified": true,
  "locale": "bg",
  "timezone": "Europe/Sofia",
  "roleKeys": ["reader"]
}
```

The `platform-consumer-sync-import.v1` result binds issuer/application/client/policy and returns mappings with `sourceUserId`, generated `subject`, snapshot `version`, `state` and `profile`. Existing role keys must belong to this application and fit policy/native-client ceilings. No platform-admin status, arbitrary role or MFA proof is imported.

Identity is bound by `(applicationId, clientId, sourceUserId)`. Replay returns the current identity without overwriting later profile/password/access changes. Unlinked existing emails conflict; no email-based acquisition or caller-selected global UUID is allowed. A batch atomically commits identities, credentials, grants, mapping and snapshots or rolls back. Invalidation events contain no profile patches.

Optional credential imports support bcrypt `$2a$`/`$2b$`/PHP `$2y$` costs 4–14, and Argon2id v19 with memory at most 65,536 KiB, iterations at most 6, parallelism at most 4, salt 8–64 bytes and digest 16–64 bytes. Unsupported/excessive hashes reject before persistence; new passwords retain Better Auth hashing. This bounded support is not a guarantee for every historical hash. Keep source hashes/private exports out of logs, commands, queues and projections.

## Laravel bootstrap and deployment

Coordinate provider and consumer SDK upgrades; this alpha uses one strict current contract. Pause affected consumers/workers during a paired rollout instead of accepting old response shapes. Apply additive provider and package migrations before enabling the new import flow.

Use the current named configuration: `identity.consumers.<name>.sync.enabled` and `.sync.import_enabled`, with the receiving client's `users.sync` and transient `users.import`. Resolve `UserImportClient` and `UserImportBootstrap` through `Identity::consumer($trustedName)`. `UserImportClient::import(array $users): UserImportResult` and `UserImportBootstrap::associate(UserImportResult $result, array $associations): array` retain the exact source-to-native proof path; each association supplies `sourceUserId`/`nativeUserId`, never email. Apply all current package association/checkpoint/native-state migrations through the host's normal release process; they do not alter native tables.

For maintained migration orchestration follow [controlled import](../IMPORTING.md): register a trusted stable read-only source, process synchronous 1–100-entry pages and preserve `runId` for same-source resume. Before dry run or import, set both `sync.provision_missing=false` and `users.lifecycle_policy=ExistingNativeOnlyLifecycle::class` (or a pure policy returning exactly false from `mayProvision('active')`). Drain/reload every affected consumer/worker; the sync flag alone does not pause JIT creation. Keep that mode until source/list exhaustion **and zero unresolved known binding/subject/native/import work**.

Dry run has zero package database/cache/transport effects, creates no persisted run and leaves provider eligibility/policy/collisions unchecked. Checkpoints retain nonsecret references/status only, never profile/credential bodies, hashes or hash-derived fingerprints. No credential exports belong in queues/logs. Checkpoint outages preserve known `runId`/remote acceptance while omitting unverifiable counters; missing counters do not mean zero. Provider/native commits remain separate: resume the same immutable source/native/provider bindings after unknown or native-association failure, without password reset or replacement identities.

Use the [typed mapping/lifecycle guide](user-synchronization.md#typed-mapping-and-ownership) for actual native columns/casts/transforms and protected key/FK/security destinations. Accepted inactive facts/session retirement commit before native projection; failed projection stays native-pending and same-version/digest retry can finish it. Public inactive apply/import refuses caller-owned outer transactions. Common physical projection writer and native-group writer are distinct. Writer/epoch edits do not transfer ownership; automated handoff refuses and would require drain, verified fencing, visibility reconciliation and a fresh authorized fetch.

After independently checking native authentication/policies/relationships and convergence, disable `users.import` and local import opt-in. The host owns credential-column/source/checkpoint retention and cutover; the package never removes native password columns. A dated profile feature receipt is historical evidence. Reusable native adoption and current-source full qualification are in progress.

Retain ordinary proxy limits; allow 16 MiB only on the exact import location with the same trusted upstream headers. Build native dependencies on the target Linux architecture. The earlier native qualification applies to its dated pre-expansion archives and does not qualify this expanded source.
