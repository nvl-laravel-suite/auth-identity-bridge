# Governed profile administration from Laravel

Resolve `Consumer\ConsumerClient` through the selected immutable consumer graph. The package remains headless: Blade, Livewire, Inertia or another host adapter owns forms, input retention and localized messages. Existing session middleware, CSRF, exact Origin and ordinary-actor boundaries still apply.

```php
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Facades\Identity;

$client = Identity::consumer('default', $request)->make(ConsumerClient::class);
$read = $client->readProfile($request, ['userId' => $targetId]);
$command = $client->updateProfile($request, [
    'userId' => $targetId,
    'expectedVersion' => $profileVersion,
    'changes' => ['name' => $name, 'phone' => null],
    'reason' => $auditReason,
    'idempotencyKey' => $originalCommandKey,
]);
```

The four helpers are `readProfile`, `readMetadata`, `updateProfile` and `updateMetadata`; all take the bound `Request` and a strict input array. Supply the expected local `context_version` in the request or `X-Identity-Context-Version` header, including for reads and recovery. This local context version is distinct from the target's shared profile `expectedVersion`. `operationStatus($request, $originalReference)` reconciles the original key. The provider owns current permissions, client ceilings, recent MFA, field policy and target eligibility.

Credentials come only from the selected confidential browser client and its ordinary actor's encrypted vault. Helpers reject delegated mode, missing selection, expired/malformed tokens and mismatched context. Initial and post-wait fences reuse the non-refreshing `SessionManager::live()` predicate: stored expiry, original-start absolute lifetime and last-activity idle lifetime must all remain valid, alongside token expiry. These observations do not refresh tokens or extend activity. Requests use the existing fixed HTTPS transport, Basic receiving-client authentication, no cookies or redirects and no generic Bearer/worker fallback. Exact issuer/application/client/**actor**/source SID bindings are checked before accepting data; `data.id` is the target.

Read input is exactly `['userId' => ...]`. Update input is exactly `userId`, positive `expectedVersion`, nonempty `changes`, trimmed 8–500-character `reason` and the original 1–128-character command key. Unknown, private and read-only fields reject before any HTTP or journal write. Omission preserves; explicit null clears only nullable fields; arrays/maps replace their selected field. Changes normalize without changing the caller's input array. Profile operations exclude metadata/security fields. Metadata operations contain only `adminNotes` and `tags`.

Managed read data is exactly `{id,version,fields,writableFields}`. The required `writableFields` list contains sorted unique canonical write-field names for that group, all present in `fields`; read-only policy returns `[]`. Use this current display hint to choose editable controls. It is not a grant or durable policy: the provider checks fresh actor/client/target authority, field policy, MFA and global-effects acknowledgement on every save. Never infer writes from readable values. `profileCompleted` is never writable; `accountType` needs explicit approved write policy, and metadata allows only `adminNotes`/`tags`. Submit only actual changes and handle field refusal, conflict, MFA and pending outcomes. Missing hints and malformed/duplicate/unsorted/cross-group hints reject; there is no older read-shape fallback. These reads and hints must never feed native field mapping.

Helpers return immutable `ManagedReadResult` or `ManagedCommandResult` objects implementing `JsonSerializable`. `ManagedFailure` exposes only safe `kind` and allowlisted/generic `code`, never raw responses, exception text, field values, audit reason or credentials. Kinds include validation, refusal, conflict, MFA, authentication, provider unavailable, context changed and recovery pending. The host retains its own original form input when a command is refused; the journal does not retain it.

| Status | Meaning |
| --- | --- |
| `read` | Validated partial `data`, with no defaults added. |
| `failed` | Local pre-send failure or a recognized provider refusal. |
| `unknown` | Commit was not established; transport failures, 5xx, invalid results and `operation_pending` do not imply rollback. |
| `pending` | Original-key status returned pending/null; this is reconciliation, not an asynchronous mutation API. |
| `committed` | Exact immutable `receipt` confirms the original target/operation/key/changed fields and expected revision plus one. |

A committed result includes `context: current|changed` and `refresh: refreshed|pending|not_required|not_configured`. Private read data is suppressed after a context/token change. Confirmed commit survives context changes, refresh failures, and later refused or pending status. A refused status for an unknown command remains unknown; MFA/auth/context errors identify that the original actor must recover authority. Never rewrite the reference to another actor/session/context or issue a new-key mutation as recovery.

The legacy `call()` API retains existing operation outputs and step-up purposes. For the new managed read names it returns validated read data as PHP arrays; for new managed update names it returns the structured command outcome array. PHP arrays alone cannot retain empty/numeric-key JSON object kinds. Prefer returning the typed read DTO through `json_encode` or the host JSON adapter: its serializer restores `data.fields` and non-null `socialLinks` as objects while preserving `tags` and `writableFields` as lists, including empty lists. Direct `$result->data` access and legacy `call()` remain PHP-array interfaces. Raw `operations.status` still supports legacy operations; a managed status additionally requires the matching retained original reference. The typed `operationStatus` helper always checks that reference and preserves commit truth.

## Durable recovery and versioned synchronization

The additive package migration `2026_11_01_000100_create_identity_consumer_commands.php` creates only `identity_consumer_commands` on the configured consumer connection. It does not alter native user schemas or provider tables. Install it through the host's normal reviewed package migration process. An unapplied/missing journal prevents managed writes from being sent.

`CommandJournal` stores a bounded reference before HTTP: fixed issuer/app/client/binding, local session, actor/central SID, selected organization/role/context version, target, operation, original expected revision/key and sorted field names. It never stores changes, reason, passwords or tokens. Receipts contain identifiers and field names only. Retention refuses inside an already-open consumer transaction: a remote command must not outlive a subsequently rolled-back local intent. Treat these recovery records as private host data and authorize any host list/detail surface.

Reusing a retained key queries its status rather than repeating the mutation, even if the process stopped before sending. A refreshed vault token may recover the original command, but actor, central SID, selected context and local context version must still match. Same-key references that differ in target/operation/version/field names reject. Uncertain or pending references must be retained until resolved; this package supplies no automatic expiration or deletion policy.

After a verified commit, the journal durably records refresh intent. With `sync.enabled`, it requests the target through existing `UserSyncManager` work and `RefreshIdentityUser` jobs; these carry only a local work-row ID. An immediate refresh attempt uses the same manager. Only a validated current versioned sync snapshot may update projections and explicitly mapped native fields. A command receipt/read result is never a native patch. Missing/invalid snapshots, provider refusal, failed native mapping or queue/work creation leave committed/pending. Queue completion is checked against the actual current work generation before reporting refreshed.

Without sync, a configured native model produces `not_configured`; without native model or sync the result is `not_required`. Neither state asserts that native data converged. `refreshed` reports completion through the existing sync owner; projection ownership/lifecycle improvements from later work remain separate.

Existing sync workers and reconciliation retry retained sync work. To repair the journal itself after queue/work creation failed, or update its refresh marker after a worker finishes, a host scheduler can resolve an explicitly selected graph and run:

```php
use IdentityPlatform\Laravel\Consumer\CommandJournal;

$journal = Identity::consumer('default')->make(CommandJournal::class);
foreach ($journal->pendingRefreshIds(100) as $commandId) {
    $journal->refresh($commandId);
}
```

This method handles **confirmed** commits through configured background sync authority only. It cannot query human operation status, acquire a browser token or infer noncommit. Unknown commands require `operationStatus` with the original ordinary source authority. A missing or removed consumer binding must not be replaced with a default graph.

## PHP and Node value parity

String bounds count UTF-16 code units like the shared Zod schemas, including astral characters. Trimming follows ECMAScript whitespace. Calendar dates include year zero when valid. `profile-timezones.json` is the frozen list generated from `['UTC', ...Intl.supportedValuesOf('timeZone')]` used by the current shared profile schema; regenerate and compare it when updating the supported Node/ICU timezone data. PHP timezone aliases do not broaden the managed allowlist.

The managed HTTP boundary preserves JSON object/list kinds before normalization: `fields` and non-null `socialLinks` must be objects; `tags`, `writableFields` and `changedFields` must be arrays. PHP callers use arrays for maps; the client explicitly serializes social-link maps, including empty/numeric-key maps, as JSON objects. Omitted PHP array keys correspond to omitted JavaScript properties; PHP has no `undefined` value.

PHP 8.4 uses the installed League URI and Guzzle URI helpers for HTTPS normalization rather than a bespoke URL parser. It normalizes host case/default port, a missing path and literal dot segments. It deliberately refuses control/space/backslash URL spellings that WHATWG may repair. WHATWG-only host spellings and encoded-dot path normalization can differ between runtimes; use canonical HTTPS URLs from the provider/browser URL serializer. Social-link object key iteration uses binary order rather than JavaScript's locale collation; JSON object key order carries no profile meaning. Neither difference widens actor, identity, credential or receipt bindings.

Qualification is isolated SQLite/Testbench plus HTTP fakes and real package sync/mapping owners. Actual provider interoperability, deployed migrations, distributed contention and full native/browser journeys require separate Root qualification. P4 does not certify later projection/lifecycle work.
