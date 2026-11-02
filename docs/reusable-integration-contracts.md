# Reusable integration contracts

This is the current execution contract for the reusable integration plan, initially frozen against the inspected 1 November 2026 source and corrected below for the P4c managed-read UI seam. Historical P0 receipts retain their original wire shape. It defines proposed APIs and migration responsibilities; it is not a claim that P1–P12 are implemented or qualified. All eight source fingerprints in the supplied plan match the inspected source.

## Authority and fields

Identity owns central shared facts. Native rows, selected presentation state and application resource context never grant central permissions. Existing self, directory, OIDC, background synchronization, app-access and central-security contracts retain their purposes.

| Field group | Self consumer | Governed profile | Governed metadata | Other authority |
| --- | --- | --- | --- | --- |
| name, locale, timezone, phone, organizationName, position, bio, dateOfBirth, gender, country, socialLinks | Existing shared read/write | Separate per-field read/write lists | Excluded | Common validators and global profile revision |
| accountType | Read-only | Explicit per-field opt-in | Excluded | Administrator/bootstrap owned; no permission effect |
| profileCompleted | Read-only | Read-field opt-in only | Excluded | Computed, never accepted as input |
| adminNotes, tags | Excluded | Excluded | Separate per-field read/write lists | Additional metadata visibility/export opt-in |
| lastLoginAt, lastLoginIp | Excluded | Excluded | Excluded | Central diagnostics; existing metadata sync may export time only |
| classification/kind, email identity/verification, password, MFA, security/provider/session facts | Existing narrow workflows only | Excluded | Excluded | Existing central security/administration |
| roles, grants, membership, suspension, deletion | Excluded | Excluded | Excluded | Existing app-access or central security workflow |

Omission preserves a field. Explicit null clears only a nullable field. Arrays/maps replace their selected field; this is not a merge patch. Unknown/read-only fields and empty changes reject. Reuse existing normalized values and bounds; do not turn accepted empty text into null implicitly. Shared profile and metadata commands use the same positive global profile revision, not application snapshot or grant versions.

## Managed operations

| Operation | POST suffix under /api/consumer/v1/ | Capability | Exact actor and client-ceiling permission |
| --- | --- | --- | --- |
| users.profile.read | app/users/profile/read | users.profile.manage | app.members.profile.manage |
| users.profile.update | app/users/profile/update | users.profile.manage | app.members.profile.manage |
| users.metadata.read | app/users/metadata/read | users.metadata.manage | app.members.metadata.manage |
| users.metadata.update | app/users/metadata/update | users.metadata.manage | app.members.metadata.manage |

All four require an enabled confidential receiving-client policy, live ordinary actor/source session, exact selected provider context, explicit assigned role when roles exist, recent management MFA no older than 300 seconds, eligible target and no delegation. Selected provider context is the exact pair of nullable organization and selected role. With null organization, both actor and target must qualify through the current direct application-grant path; organization grants cannot substitute. With non-null organization, both must qualify through that exact selected organization: the organization and membership must be active, approval current and the application grant active; direct grants or another organization's path cannot substitute. No cross-path fallback is allowed. A null/omitted role is valid only for genuinely roleless access in that selected context, never a union or implicit selection of assigned roles. The target does not inherit the actor's selected role. Existing client/organization ceilings and direct denials remain effective. These control-plane operation names cannot be registered as delegated business operations.

Target eligibility requires an active human/person identity, active application and valid current association in the exact selected context. Missing, foreign, inactive, non-person, platform-admin, current organization owner/admin and protected-app-role targets receive the same non-disclosing resource-unavailable result. Privileged-target checks cover active privileged assignments across contexts because the edited facts are global. A platform administrator using the consumer plane receives no bypass. A same-person request may pass only the identical managed authority/field/target checks; it never falls back to self-service authority.

Read input is exactly `{userId}`. Read data is exactly `{id,version,fields,writableFields}`, with only the authorized read fields and no defaults synthesizing absent fields. Required `writableFields` is a JSON array of unique, deterministically sorted canonical write-field names for that group, restricted to keys actually returned in `fields`. It comes from the same locked current actor/client/target/field-policy check as the values. Read-only policy returns `[]`; missing hints are invalid in this current-only alpha. `profileCompleted` is never writable, `accountType` requires explicit approved write policy, and metadata hints contain only `adminNotes`/`tags`. This is current UI information, never a grant or durable policy: each save independently rechecks current authority, shared/global-effects acknowledgement, MFA and field policy. Consumers submit only actual changes and handle field refusal, conflict, MFA and pending outcomes. Neither these values nor hints are native field-mapping input. No caller-supplied actor, issuer, app, client, source SID or arbitrary field selector is accepted.

Update input is exactly `{userId,expectedVersion,changes,reason,idempotencyKey}`. Reason is trimmed PostgreSQL-safe text, 8–500 characters. Existing idempotency syntax remains 1–128 `[A-Za-z0-9_.:-]` characters. Normalize before computing the bound command digest. A successful command advances revision once and returns exactly `{id,version,operation,idempotencyKey,changedFields}`; fields are sorted, unique and nonempty, with no values or reason. Immediate version is expectedVersion+1; replay returns the original receipt without treating its old expectedVersion as a new mutation.

The existing outer result remains `platform-consumer-result.v1`, bound to exact issuer/application/client/**actor**/source SID. Target identity belongs in data.id. Reads and receipt/status results get shared strict Zod and equivalent PHP validators. Node transport is exported only through `@identity/client/server`.

### Policy fields

- `managedProfileReadFields`: unique subset of the eleven shared editable keys plus accountType and profileCompleted; default [].
- `managedProfileWriteFields`: unique subset of the eleven editable keys plus accountType; default [].
- `managedMetadataReadFields`, `managedMetadataWriteFields`: unique subsets of adminNotes/tags; default [].
- `managedProfileGlobalEffectsAcknowledged`: boolean, default false, required for either group of global writes.

Write fields must be a subset of read fields. Empty read lists deny that operation group. Capability enablement requires its exact app permission in the client ceiling/catalog; field lists alone grant nothing. Metadata manage additionally requires users.sync and users.sync.metadata. Neither existing read/export permission grants managed mutation. Read-only policies may leave writes empty and acknowledgement false. Derive capability limits and presentation choices from the enum; there are no wildcard fields or fixed nine-item ceiling.

These lists govern the new human operations. They do not narrow facts independently granted by existing directory/self/sync capabilities. Adding field-limited background export would require a separate explicit projection/hash/redaction contract.

### Publication, status and failure

Use the existing policy fence, actor/source checks, target locks, profile revision, audit and invalidation/outbox transaction. Recheck policy, token/source deadlines, selected context, MFA, permissions, target eligibility and version after resource waits and before commit. Do not call broad central administration as a substitute for consumer authority.

Persist receipt-only results and bounded target/changed-field references for new managed mutations. Both replay and operations.status recheck the retained operation's **current** authority, target and field policy. Pending status has null data; completed status has its matching strict receipt. No historical profile/metadata values are returned after revocation. The existing atomic mutation is not advertised as an asynchronous job API.

Reason belongs to private central audit, while external invalidation payloads contain no reason text or profile values. Keep audit/publication atomic with separate safe external metadata.

Preserve existing error envelope/status conventions. New refusals are `consumer_profile_field_denied` and `consumer_global_effect_acknowledgement_required` (403). Target failure is uniformly `consumer_resource_unavailable` (404); version/idempotency/context conflict remains 409; malformed input 400; MFA, source/token and infrastructure outcomes retain their existing typed owner. No raw input or credential is echoed.

Unknown commit reconciles the original key/status. Committed provider work followed by native refresh failure returns committed/refresh-pending and retains durable authorized refetch; it never repeats the write with a new key. Native mapping consumes a validated versioned sync snapshot, never command response fields.

## Immutable named consumers

The sole canonical configuration has root `default_consumer`, `connection`, `consumers` and `service_targets`. Each consumer contains origin/app_origin/application_id, browser, resource, session, routes, callbacks, users, sync, local, delegation, lock_store and http. Reject old flat credential/origin configuration, unknown keys, closures, runtime objects, partial credential pairs and invalid registered class strings.

Preserve independently configured resource/service use without unused browser credentials. An explicit resource-only consumer has null browser/session/routes, a complete resource pair, disabled sync/import/provisioning and no native/projection ownership; it has no browser binding or byBinding registration. A service-only root may have empty consumers and null default_consumer. Nonempty consumers require a registered default. The service-target registry is independently constructible. These are explicit credential-plane modes, not fallback to another plane.

`ConsumerContext` is immutable. `ConsumerRegistry::get(name)` and `byBinding(hash)` resolve trusted known definitions. An explicit factory constructs a graph for that context; no global identity configuration is rewritten. The registry contains no selected request, guard, token or principal. Default selection cannot rescue unknown hosts, missing console selection or unknown persisted work.

Binding hash remains SHA-256 over the exact existing five NUL-separated values: issuer, browser client ID, application ID, app origin, effective Laravel cookie name. Consumer name and mutable credential secret are excluded. Unchanged bindings therefore retain their meaning; changed or ambiguous bindings fail safely. Duplicate hashes and ambiguous host/path/route mappings reject rather than guessing.

Selection uses explicit trusted exact HTTPS origin/host/port and configured path/route mappings before session/auth and context-dependent controller construction. Verify route binding matches early selection. Request body/query/header consumer names, token claims and unsigned event fields do not select credentials. A middleware ordering claim alone is insufficient if controller DI resolves managers earlier.

Validate exact registered callback/logout/event/back-channel URLs and deterministic `identity.<consumer>.<action>` route names. Browser contexts have independent cookies/stores/guard resolution. Host-only Secure HttpOnly SameSite=Lax with path / is the default; validate explicit alternatives and __Host- requirements, reject overlapping cookie names/scopes, and never silently broaden a domain.

If Laravel requires temporary session configuration, one narrow adapter installs only validated framework session settings, clears resolved stores/guards, completes the inner cookie/session pipeline and restores exact settings/references in finally, including exceptions. Identity credentials/config never mutate. Sequential-worker tests are required; concurrent coroutine isolation requires task-local state or a mutation-free adapter and is not implied by finally cleanup.

One package/native consumer connection remains supported. Laravel session-store connection is a distinct setting. Contexts do not promise cross-database atomicity. Named configuration publishes complete values for cookie/session driver/store/table/encryption/lifetime, exact endpoints, explicit adapter classes, sync opt-ins, local deadlines and trusted HTTP/lock settings; cache contains only scalars/arrays/class strings.

Queue and console operations select explicitly. Jobs retain only local row references: load row binding first, resolve registry, then construct its graph. Missing row can be idempotent; a present row with unavailable/changed context remains a diagnosable retry/refusal. Callback receipts already carry binding+protocol+message identity; preserve this. Any app-wide fanout is an explicit trusted configured set with independent per-member verification and effects, never recipients selected by payload claims.

## Native projection, import and lifecycle

Compile a typed mapping definition from canonical sources to explicit native destinations, registered transforms and casts. Keep direct mapping as the simple case. Protect actual primary/owner/foreign keys, credentials, role/permission/security and host-owned/read-only fields. Keep absent/null/redacted facts distinct. Default provisioning/lifecycle policy retains rows and refuses implicit restoration or email acquisition.

Accepted binding version/digest/lifecycle is separate from native-applied version/status/failure. An accepted inactive state and session retirement commit even if native lookup or display mapping fails. Same-version retry may finish pending projection without changing accepted facts; it must recheck accepted version and ownership fence. Active creation/association stays atomic. Outer import transactions must not accidentally roll back accepted inactive security state.

Application sync versions are not globally comparable. Freeze two independent projection ownership units:

- The physical shared `IdentityUser` row is keyed by issuer/subject. Across **all** configured consumers for an issuer, exactly one registered consumer binding and ownership epoch may write its mutable common facts, including when consumers use different native owners, disjoint native groups or no native mapping. Each consumer's `users.identity_projection_writer` names the same registered consumer for its issuer; a single consumer names itself. The setting belongs under `consumers.<name>.users`, preserving the four root keys. Reject missing, unknown, foreign-issuer or conflicting writer declarations during registry validation. Resolve the named writer to its exact binding and enforce the ownership epoch at the shared destination.
- Each approved shared native destination group separately has exactly one registered writer binding and ownership epoch. Its writer need not be the common `IdentityUser` writer. Disjoint native destinations have independent native ownership; they do not create additional writers for the shared issuer/subject row. A consumer without native mapping still declares the common writer and participates in that ownership rule, but has no native destination to project.

Nonwriters never update the respective shared destination's mutable fields, including through JIT or unversioned UserInfo paths. Immutable issuer/subject identity association remains available to every binding; association does not authorize common-field or shared-native writes. Each binding retains its own accepted facts/version/digest/lifecycle and retires its own sessions. Binding-specific native projection and presentation consume that binding's accepted state, never mutable common facts last written by another application. Protected metadata remains binding-scoped; visibility in one binding does not authorize disclosure through common fields or another binding's native mapping/presentation. One application's lifecycle cannot competitively drive a shared whole-person active flag.

Transfer of either writer requires an explicit owner-locked epoch handoff: stop/drain the prior owner's work, fence out its old epoch, install the new binding/epoch and refetch fresh authorized state before projection resumes. Every write or pending retry checks the destination's current writer binding/epoch; last arrival and comparisons of different applications' versions cannot decide ownership. Reuse existing projection, binding-state and association storage/interfaces where possible; this freeze does not implement P5 or introduce a duplicate sync store.

Existing explicit import/client/bootstrap and reconciliation remain the mechanics. `UserImportSource` is selected from trusted registration and yields bounded source/native associations; `ImportRunner` adds preflight, dry run and resumable synchronous batches. Persist only consumer binding, non-secret run/cursor/source/native/mapping references, counters and sanitized errors. Never persist source password hashes, request bodies or actor tokens. Provider commit/local failure resumes via the same source bindings and supplied native IDs. Success requires exhausted traversal and zero unresolved work, not one page or an exit code. Disable import capability/local opt-in after cutover.

## Service targets and public application APIs

`ServiceTokenManager::target(name)` selects a trusted independent definition: provider origin, target application/audience, fixed downstream base URL, issuing worker client/secret, permitted scopes and HTTP/cache policy. No browser-app or credential-family fallback. P1 supplies immutable target/transport foundations so the current-only config transition remains coherent; P7 adds the public manager and final cache/attachment behavior.

Issuer/audience/client/credential generation/normalized scopes bind cache and locks. Reject and revoke compare the matching token generation before eviction. Fixed-origin attachment refuses request-selected destinations and redirected credential forwarding. Preserve delegated outbound/queue refusal. Equivalent Node APIs stay server-only and require host execution-policy/cache/locking adapters; they cannot claim Laravel's ambient guard automatically.

Public headless lifecycle wraps existing session, context-selection, logout and delegation owners. Safe events follow successful state changes; optional listener failure cannot undo security changes or repeat an authentication exchange. A redirect resolver preserves local/same-origin returns. Another surface starts an independent OIDC session.

The state presenter contains only named consumer, safe actor/effective identity, selected org/role, context version, finite current display permissions, nullable application-context descriptor and finite delegation status/expiry. No token/handle, usable vault identifier, raw snapshot or full ledger is serialized. Blade/JSON and Inertia/Livewire recipes consume public DTOs without adding framework dependencies.

Named ability ownership composes current central checks with required native resource policy. Central refusal is final; central allow continues through business/ownership checks. Unmapped/local ownership is explicit. No stale local admin/Spatie table or middleware-only shortcut replaces current authority and write fencing.

Application-context descriptor is `{kind,resourceId,label,consumerBinding,actorSubject,providerSelection,version,expiresAt}` with only safe bounded values; providerSelection is the current nullable organization/role pair. Registered host providers own eligibility. List/select/current/clear use the existing session version/fence; selection is CSRF/Origin-protected and revalidated on use and before mutation. Clear on source/actor/provider selection/delegation changes unless explicitly revalidated. Remembered resource ID narrows routing, never grants authority.

## Execution and evidence

The P0 caller inventory identifies 41 direct PHP IdentityConfig consumers plus binding lookups, vault purposes, queues, callbacks and ambient resolutions. Existing binding-aware tables are extended only for a demonstrated missing responsibility; do not add a duplicate session/sync/authorization store.

Later implementation acceptance must cover the following contracts; these are future cases, not P0 execution evidence:

- Two consumers with the same issuer/subject and different native owners (including disjoint native groups) accept their own binding state while only the declared common writer updates `IdentityUser`; each native destination uses its own accepted binding facts and ownership. Repeat with two consumers without native mapping and with one mapped and one unmapped consumer. Reject conflicting common-writer declarations. Exercise JIT/unversioned UserInfo and pending retries from nonwriters, distinct common/native writers, protected metadata isolation and owner-locked transfer with old-epoch work refused.
- Managed reads, writes, replay and status preserve null-organization direct-grant authority and exact non-null organization-grant authority for both actor and target. Cover eligible direct and organization paths, missing/inactive membership/approval/grant paths, grants available only through the other path or another organization, assigned-role selection and genuinely roleless null-role selection. Refuse cross-path fallback and recheck the exact context after waits and before commit.

The strict transition covers published/sample config, package Testbench/Postgres fixtures, native sample routes/middleware/views/tests, queue/console entry points, root PHP import/bootstrap helpers, Node contracts/server client, provider UI and capability/docs/skills. Independent examples remain presentation-neutral and synthetic. P1–P12 require their own red/green invariant tests and separate package/sample/protocol/browser/real-contention receipts. P0 performed source inspection and documentation work only; no live migrations, stores, credentials or HTTPS/HTTP2 settings changed.
