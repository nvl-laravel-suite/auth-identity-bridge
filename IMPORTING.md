# Controlled native-user import

Import is a synchronous, explicitly enabled migration operation. The provider requires the receiving confidential client's `users.import` **and** `users.sync` capabilities. New-source governance metadata additionally requires `users.sync.metadata`; role keys must already exist and fit the receiving application's policy. Local `sync.enabled` and `sync.import_enabled` must both be true for the named consumer. Import does not grant human management authority, acquire an existing identity by email, restore deleted native rows, or transfer ownership.

Apply the package migrations through the host's normal reviewed migration process, including `2026_11_01_000300_create_identity_import_checkpoints.php`. They add package ledgers only. No import command alters a host table, removes password columns, changes HTTPS settings, or applies migrations.

## Pause automatic native creation

Before import or dry run, set the named consumer's `sync.provision_missing` to `false` and `users.lifecycle_policy` to `IdentityPlatform\Laravel\Users\ExistingNativeOnlyLifecycle::class`. A host-owned pure `NativeLifecyclePolicy` whose `mayProvision('active')` returns exactly `false` is also supported. The runner enforces both conditions before cache/database writes, source execution or HTTP. The sync flag alone does not pause JIT creation.

The supplied policy refuses creation through the existing native resolver while retaining the normal mapping/soft-delete checks for already linked users and explicit bootstrap associations. This preserves original native IDs and host foreign keys if a provider commit is known only after replay.

Drain in-flight JIT/provisioning and sync workers and reload **all consumers of the affected native store** with the paused configuration before starting. Keep creation paused until source exhaustion, association checkpoints and all unresolved import/sync work are complete. Restore the normal policy only through the host's explicit cutover after that proof. The package cannot retroactively stop an old process retaining its prior immutable configuration, or prevent an operator from unpausing early; that unsupported action can race explicit association and force an ownership refusal. This policy is a controlled migration precondition, not an automated distributed drain/fence system.

## Register a trusted source

A source implements `UserImportSource::page(?string $cursor, int $limit): UserImportPage`. Register its class under a trusted name in the host container; CLI input cannot select arbitrary classes. Keep the registry singleton in the host, and resolve source dependencies through the selected consumer graph.

```php
use App\Identity\PeopleImportSource;
use IdentityPlatform\Laravel\Sync\UserImportSourceRegistry;

$this->app->singleton(UserImportSourceRegistry::class, function () {
    $sources = new UserImportSourceRegistry;
    $sources->register('people', PeopleImportSource::class);
    return $sources;
});
```

The host source explicitly chooses the records and exact native IDs. This example assumes a host model with `id`, `display_name`, and `contact_email`; replace those choices in the adapter, not in package code. A UUID model or another schema uses its own adapter and the same package interfaces. Configure the named consumer's `users.model` and canonical `users.fields` to match that native model.

```php
namespace App\Identity;

use App\Models\MigrationPerson;
use IdentityPlatform\Laravel\Sync\UserImportEntry;
use IdentityPlatform\Laravel\Sync\UserImportPage;
use IdentityPlatform\Laravel\Sync\UserImportSource;

final class PeopleImportSource implements UserImportSource
{
    public function page(?string $cursor, int $limit): UserImportPage
    {
        $rows = MigrationPerson::query()
            ->when($cursor !== null, fn ($query) => $query->where('id', '>', $cursor))
            ->orderBy('id')->limit($limit + 1)->get();
        $batch = $rows->take($limit);

        return new UserImportPage(
            $batch->map(fn ($row) => new UserImportEntry([
                'sourceUserId' => 'native:'.$row->getKey(),
                'name' => $row->display_name,
                'email' => $row->contact_email,
                'emailVerified' => false,
            ], $row->getKey()))->all(),
            $rows->count() > $limit ? (string) $batch->last()->getKey() : null,
        );
    }
}
```

Sources, constructors, model accessors/mutators and registered transforms are trusted host code: they must be read-only while exporting/preflighting, must not log or serialize exports, and must not call network services. The package cannot make an arbitrary host implementation pure. IDs must be stable, nonsecret and never reused for a different person. Cursors must be stable, nonsecret keyset positions, 1–1024 characters from `A-Za-z0-9_.:/-`; native IDs use 1–255 `A-Za-z0-9_.:-` characters. Freeze the export membership/order for a run. Do not use emails, passwords, token material, hashes, hash-derived fingerprints or raw encoded payloads as IDs/cursors. Changing a reserved source/native binding is refused even if the first remote outcome was uncertain.

A page contains at most the requested 1–100 entries, with a null next cursor on exhaustion. An empty page must be final. Repeated source IDs within/across pages, changed pending-page membership/order/next cursor, repeated cursor pages and changed native owners fail safely. A resumed run requires the same consumer binding/name, registered source name/class and batch size. A new run starts at the beginning and reuses the immutable source/native/provider bindings; changing its name is not a way to acquire the same native rows.

## Validate, run and resume

```sh
php artisan identity:users-import --consumer=workspace --source=people --dry-run
php artisan identity:users-import --consumer=workspace --source=people --limit=100 --max-pages=1000
php artisan identity:users-import --consumer=workspace --source=people --limit=100 --resume=RUN_ID
php artisan identity:users-reconcile --consumer=workspace --limit=100 --max-pages=1000
```

Dry run validates the selected source, whole bounded batches, supported hashes, existing native rows, current local owner/import bindings, the public mapping schema, registered transforms/casts, and required mapped native values. It performs no package database/cache/transport writes and does not create a run. Trusted source code has the read-only obligations above. It reports `remoteChecks: "unverified"` and `completed: false`: provider eligibility, current policy, role/metadata permission and existing-email collisions require actual authorized transport. Exit zero for dry run means local validation exhausted the source; it is not migration convergence. A bounded partial dry run exits nonzero. Dry run cannot resume a persisted run.

Real execution validates an entire page before reserving its immutable references or contacting the provider. Validation is advisory against concurrent native/owner changes; the existing bootstrap rechecks under its transaction locks. Missing and soft-deleted native rows, required mapped nulls, protected/missing columns and owner conflicts fail the page without merging/restoring anything. Failed output includes safe source/native IDs for the attempted batch, never emails or profile/credential bodies. Unexpected host/provider/SQL exception text is replaced by a safe code.

The default invocation processes at most 1,000 pages (configurable 1–10,000); batch size is 1–100. `runId` enables a later invocation to continue. A page budget is a partial result, not success. Keep the run ID in ordinary operational records; it contains no credential. Sources and the runner execute synchronously. `UserImportEntry` and `UserImportPage` redact debug output and refuse PHP serialization; the runner also refuses serialization. Do not extract their payload arrays into jobs, logs or export files. The host must configure HTTP/APM logging to exclude credential-bearing request bodies.

## Commit and recovery boundaries

1. A consumer transaction reserves the exact source/native bindings and ordered page references before HTTP. The run/page/entry/binding ledgers contain only nonsecret references, cursors, statuses, counts and safe codes. They contain no email/profile bodies, reasons, passwords/hashes, hash-derived credential fingerprints, provider responses or actor/browser credentials.
2. The provider atomically imports its batch under the existing `(applicationId, clientId, sourceUserId)` identity binding. Replaying that binding returns the current identity and does not overwrite later passwords/profile/access. Provider and native commits are separate.
3. A validated response's inactive facts and session retirement are accepted through the existing security transaction before checkpoint/native mapping. A failure afterward cannot undo that accepted denial. The checkpoint then saves only source-to-provider IDs and requests durable current-profile work.
4. `UserImportBootstrap::associate` consumes the typed response and exact supplied native IDs. It owns the local association transaction and `UserImportLink` rows. The runner never fabricates association proofs or import-link rows. Mapping/association failure leaves the original page resumable and does not turn accepted inactive security into applied native state.
5. A successful native transaction is followed by the page checkpoint. Work completes only for the generation captured before bootstrap, with no native-pending state; a newer concurrent generation stays pending. If the final checkpoint fails, replay uses the same source bindings and existing associations.

`imported` counts durably known provider mappings; `associated` counts known native associations. `applied`/`stale` describe recorded native page outcomes, not new provider identities. `providerAcceptedInLastAttempt` reports a validated response even if its mapping checkpoint failed. `remoteOutcome` distinguishes `not_attempted`, `accepted`, `refused` (an exact known precommit public rejection), and `unknown`. A generic 4xx/5xx, timeout, oversized response (including HTTP 413), or `consumer_import_snapshot_unavailable` can follow a commit and stays unknown. Never infer rollback from the status alone. Keep the original source IDs and native associations and resume; do not create replacement identities or reset passwords. Reservations survive checkpoint failures. Known commits omit password hashes on subsequent requests; uncertain commits use the same provider keys, whose provider replay semantics prevent credential reapplication. Payload changes are not fingerprinted or retained, so the source's stable-export obligations remain essential.

A cache lease serializes normal imports for a binding. Durable unique reservations and bootstrap ownership checks remain the authority if a worker loses its lease. Production database contention and multi-process lease behavior need host qualification; isolated SQLite tests are not that proof. Host query/mapping errors can still arise after remote commit despite local preflight.

If checkpoint writes (including the failure-status write), final reporting reads, or lease release become unavailable after a run is known, the runner returns a limited safe result: `runId`, `remoteOutcome`, `providerAcceptedInLastAttempt`, `completed: false`, `error: "user_import_checkpoint_unavailable"`, `checkpointStatus: "unavailable"`, and the attempted batch's nonsecret IDs. Durable/native counters and exhaustion are omitted because they could not be verified. The command emits that result and exits nonzero. Preserve the run ID and resume with the same source when the store recovers; a missing counter is not zero or proof of rollback.

## Reconciliation and completion

Reconciliation explicitly selects a consumer and traverses list/known-user pages within its budget. It reports imported/associated totals, applied/stale attempts, missing, pending, failed and `nativePending`. Applied counts may include both a known-user refresh and a list observation of the same person; do not add them to infer distinct people. Unknown/native errors are sanitized. A repeated cursor stops with failure rather than looping indefinitely.

Completion requires source/list exhaustion **and zero unresolved known work**, including incomplete subject/binding generations, accepted-but-native-pending projections and unresolved import reservations for the binding. Starting an empty run cannot hide an older unresolved import; reconciliation reports those reservations as `unresolvedImports`. Exhausting 100 rows, observing an accepted snapshot, or returning from a worker does not establish convergence. Missing provider profiles remain unresolved; they are not deletion instructions. An exhausted import with later pending synchronization may need explicit reconciliation before its run summary can become complete. A failed association page still needs the same-source import resume to establish its proof. Neither command clears work generations to force a successful result.

## Cutover and retention

Freeze the source set, run local checks, import/resume to exhausted references, and reconcile current authorized snapshots until unresolved native/work counts are zero. Independently verify host authentication, native policies and expected user relationships. Then remove `users.import` from the receiving client and disable local `sync.import_enabled`; retain `users.sync` only if ongoing synchronization is intended. A later bootstrap attempt requires explicit re-enablement. Run/checkpoint/reference retention is a host operational decision; no package command automatically deletes those immutability records.

Source credential retention and disposal belong to the host's reviewed cutover process. The package never stores credential exports or decides when to drop a host's password columns, legacy identifiers or domain relationships. Take the host's recovery/audit obligations into account without storing new credential copies in these ledgers.

Writer changes are not ownership transfer. Current `ProjectionOwnership::transfer` deliberately refuses automatic handoff. A future coordinated handoff needs prior-worker drain, verified writer/epoch fencing, reconciliation of visibility-controlled fields and a fresh authorized fetch under the new writer before publication. Automated drain/epoch/fresh-fetch handoff is not implemented here. Do not edit ownership/import ledgers manually or clear accepted lifecycle facts to simulate it.

See the [synchronization recipe](docs/user-synchronization.md), [provider import contract](docs/profile-and-user-bootstrap.md), and [frozen integration boundaries](docs/reusable-integration-contracts.md). Package HTTP-fake/SQLite tests prove local orchestration only; they do not establish live provider, browser, PostgreSQL/MySQL concurrency or deployment acceptance.
