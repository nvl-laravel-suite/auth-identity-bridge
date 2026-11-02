<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\ExecutionPolicy;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Support\Facades\Cache;
use Throwable;

/** Synchronous only: checkpoints contain references, never source exports.
 * @api
 */
class ImportRunner
{
    public function __construct(private IdentityConfig $config, private ImportPreflight $preflight, private ImportCheckpointRepository $checkpoints, private UserImportClient $client, private UserImportBootstrap $bootstrap, private UserSnapshotRepository $snapshots) {}

    /** @return array{runId: string, imported: int, associated: int, applied: int, stale: int, missing: int, pending: int, nativePending: int, unresolved: int, failed: int, error: string|null, exhausted: bool, completed: bool, providerAcceptedInLastAttempt: int, remoteOutcome: string, failedBatch: list<array{sourceUserId: string, nativeUserId: string}>}|array{runId: string, remoteOutcome: string, providerAcceptedInLastAttempt: int, completed: false, error: string, checkpointStatus: string, failedBatch: list<array{sourceUserId: string, nativeUserId: string}>}|array{runId: null, dryRun: true, validated: int, exhausted: bool, completed: false, remoteChecks: string} */
    public function run(string $sourceName, #[\SensitiveParameter] UserImportSource $source, ?string $resume = null, bool $dryRun = false, int $limit = 100, int $maxPages = 1000): array
    {
        try {
            return $this->execute($sourceName, $source, $resume, $dryRun, $limit, $maxPages);
        } catch (Throwable $error) {
            throw new IdentityException(self::safeCode($error), $error instanceof IdentityException ? $error->status : 503);
        }
    }

    /** @return array{runId: string, imported: int, associated: int, applied: int, stale: int, missing: int, pending: int, nativePending: int, unresolved: int, failed: int, error: string|null, exhausted: bool, completed: bool, providerAcceptedInLastAttempt: int, remoteOutcome: string, failedBatch: list<array{sourceUserId: string, nativeUserId: string}>}|array{runId: string, remoteOutcome: string, providerAcceptedInLastAttempt: int, completed: false, error: string, checkpointStatus: string, failedBatch: list<array{sourceUserId: string, nativeUserId: string}>}|array{runId: null, dryRun: true, validated: int, exhausted: bool, completed: false, remoteChecks: string} */
    private function execute(string $sourceName, #[\SensitiveParameter] UserImportSource $source, ?string $resume, bool $dryRun, int $limit, int $maxPages): array
    {
        app(ExecutionPolicy::class)->assertOutboundAllowed();
        Contract::require($this->config->value('sync.enabled', false) === true && $this->config->value('sync.import_enabled', false) === true, 'user_import_disabled', 404);
        Contract::require(preg_match('/^[a-z][a-z0-9_-]{0,63}$/D', $sourceName) === 1, 'user_import_source_invalid', 422);
        Contract::require($limit >= 1 && $limit <= 100 && $maxPages >= 1 && $maxPages <= 10000, 'user_import_limit_invalid', 422);
        Contract::require(! $dryRun || $resume === null, 'user_import_dry_resume_invalid', 422);
        $this->preflight->assertPausedProvisioning();
        $this->checkpoints->assertStandalone();
        if ($dryRun) {
            return $this->dryRun($sourceName, $source, $limit, $maxPages);
        }
        $store = Cache::store($this->config->value('lock_store'))->getStore();
        Contract::require($store instanceof LockProvider, 'user_import_busy', 409);
        $lock = $store->lock('identity-import:'.$this->config->bindingHash(), 60);
        Contract::require($lock->get() === true, 'user_import_busy', 409);
        $run = null;
        $providerAccepted = 0;
        $remoteOutcome = 'not_attempted';
        $failureIds = [];
        $checkpointUnavailable = false;
        try {
            $run = $this->checkpoints->open($sourceName, $source::class, $resume, $limit);
            for ($number = 0; $number < $maxPages && ! $run->exhausted; $number++) {
                $this->lease($lock);
                $providerAccepted = 0;
                $remoteOutcome = 'not_attempted';
                $page = $source->page($run->cursor, $limit);
                Contract::require(array_is_list($page->entries()) && count($page->entries()) <= $limit, 'user_import_input_invalid', 422);
                $failureIds = [];
                foreach ($page->entries() as $entry) {
                    if ($entry instanceof UserImportEntry && Contract::identifier($entry->payload()['sourceUserId'] ?? null) && preg_match('/^[A-Za-z0-9_.:-]{1,255}$/D', (string) $entry->nativeUserId)) {
                        $failureIds[] = ['sourceUserId' => $entry->payload()['sourceUserId'], 'nativeUserId' => (string) $entry->nativeUserId];
                    }
                }
                // Detect repeated source IDs before immutable-binding validation for actionable classification.
                foreach ($page->entries() as $entry) {
                    if (! $entry instanceof UserImportEntry) {
                        continue;
                    }
                    $sourceId = $entry->payload()['sourceUserId'] ?? null;
                    if (! is_string($sourceId)) {
                        continue;
                    }
                    $this->checkpoints->checkSource($run, $sourceId);
                }
                $references = $this->preflight->page($page, $sourceName, $run->cursor, $limit);
                $this->lease($lock);
                $checkpoint = $this->checkpoints->reserve($run, $references, $page->nextCursor);
                if ($references === []) {
                    $this->checkpoints->advance($run, $checkpoint);
                    break;
                }
                $users = [];
                foreach ($page->entries() as $index => $entry) {
                    Contract::require($entry instanceof UserImportEntry, 'user_import_input_invalid', 422);
                    $payload = $entry->payload();
                    // Known commits do not retransmit hashes. Unknown commits replay the same stable provider key.
                    if ($this->checkpoints->knownSubject($references[$index]['id'])) {
                        unset($payload['passwordHash']);
                    }
                    $users[] = $payload;
                }
                $this->lease($lock);
                $remoteOutcome = 'unknown';
                $this->checkpoints->attempting($run);
                $result = $this->client->import($users);
                $remoteOutcome = 'accepted';
                unset($users, $payload, $page);
                $providerAccepted = count($result->mappings);
                $this->snapshots->acceptInactive(array_map(fn ($mapping) => $mapping->snapshot, $result->mappings));
                $work = $this->checkpoints->accepted($run, $result);
                $this->lease($lock);
                $outcomes = $this->bootstrap->associate($result, array_map(fn ($reference) => ['sourceUserId' => $reference['source_user_id'], 'nativeUserId' => $reference['native_user_id']], $references));
                $this->lease($lock);
                $this->checkpoints->finish($run, $checkpoint, $result, $outcomes, $work);
            }
        } catch (Throwable $error) {
            $code = self::safeCode($error);
            if ($remoteOutcome === 'unknown' && in_array($code, ['consumer_import_email_conflict', 'consumer_import_password_unsupported', 'consumer_import_role_denied', 'consumer_import_metadata_denied', 'consumer_import_disabled'], true)) {
                $remoteOutcome = 'refused';
            }
            if ($run === null) {
                throw new IdentityException($code, 409);
            }
            // Even a failed post-commit checkpoint is replayable through the durable pretransport reservation.
            try {
                $this->checkpoints->failed($run, $code, $remoteOutcome, $providerAccepted);
            } catch (Throwable) {
                $checkpointUnavailable = true;
            }
        } finally {
            try {
                $lock->release();
            } catch (Throwable) {
                // A database-backed lease may fail with the same store outage. Keep already known facts.
                $checkpointUnavailable = true;
            }
        }

        if (! $checkpointUnavailable) {
            try {
                return [...$this->checkpoints->summary($run), 'providerAcceptedInLastAttempt' => $providerAccepted, 'remoteOutcome' => $remoteOutcome, 'failedBatch' => $run->error_code === null ? [] : $failureIds];
            } catch (Throwable) { /* Reporting cannot discard a validated provider result. */
            }
        }

        return $this->unavailableCheckpoint($run, $remoteOutcome, $providerAccepted, $failureIds);
    }

    /** In-memory facts only: durable/native counts and exhaustion cannot be inferred during an outage. */
    /**
     * @param  list<array{sourceUserId: string, nativeUserId: string}>  $failureIds
     * @return array{runId: string, remoteOutcome: string, providerAcceptedInLastAttempt: int, completed: false, error: string, checkpointStatus: string, failedBatch: list<array{sourceUserId: string, nativeUserId: string}>}
     */
    private function unavailableCheckpoint(ImportRun $run, string $remoteOutcome, int $providerAccepted, array $failureIds): array
    {
        return ['runId' => $run->id, 'remoteOutcome' => $remoteOutcome, 'providerAcceptedInLastAttempt' => $providerAccepted,
            'completed' => false, 'error' => 'user_import_checkpoint_unavailable', 'checkpointStatus' => 'unavailable', 'failedBatch' => $failureIds];
    }

    /** @return array{runId: null, dryRun: true, validated: int, exhausted: bool, completed: false, remoteChecks: string} */
    private function dryRun(string $name, #[\SensitiveParameter] UserImportSource $source, int $limit, int $maxPages): array
    {
        $cursor = null;
        $seenCursors = [];
        $seenSources = [];
        $seenNative = [];
        $validated = 0;
        for ($number = 0; $number < $maxPages; $number++) {
            Contract::require(! isset($seenCursors[$cursor ?? '']), 'user_import_cursor_invalid', 422);
            $seenCursors[$cursor ?? ''] = true;
            try {
                $page = $source->page($cursor, $limit);
                $references = $this->preflight->page($page, $name, $cursor, $limit);
            } catch (Throwable $error) {
                throw new IdentityException(self::safeCode($error), 422);
            }
            foreach ($references as $reference) {
                Contract::require(! isset($seenSources[$reference['id']]), 'user_import_duplicate_source', 422);
                Contract::require(! isset($seenNative[$reference['physical_key']]), 'user_import_owner_conflict', 422);
                $seenNative[$reference['physical_key']] = true;
                $seenSources[$reference['id']] = true;
            }
            $validated += count($references);
            $cursor = $page->nextCursor;
            if ($cursor === null) {
                break;
            }
        }

        return ['runId' => null, 'dryRun' => true, 'validated' => $validated, 'exhausted' => $cursor === null, 'completed' => false, 'remoteChecks' => 'unverified'];
    }

    private function lease(Lock $lock): void
    {
        Contract::require(method_exists($lock, 'refresh') && $lock->refresh(60) === true, 'user_import_busy', 409);
        app(ExecutionPolicy::class)->assertOutboundAllowed();
    }

    public static function safeCode(Throwable $error): string
    {
        $allowed = ['delegation_outbound_forbidden', 'user_import_checkpoint_unavailable', 'user_import_disabled', 'user_import_provisioning_enabled', 'user_import_input_invalid', 'user_import_hash_unsupported', 'user_import_binding_changed', 'user_import_association_invalid', 'user_import_association_conflict', 'user_import_association_unavailable', 'user_import_native_missing', 'user_import_native_soft_deleted', 'user_import_native_required', 'user_import_owner_conflict', 'user_import_cursor_invalid', 'user_import_duplicate_source', 'user_import_run_invalid', 'user_import_run_changed', 'user_import_busy', 'user_import_source_invalid', 'user_import_source_unknown', 'user_import_limit_invalid', 'user_import_dry_resume_invalid', 'identity_user_mapping_invalid', 'native_transform_invalid', 'identity_user_connection_mismatch', 'identity_projection_owner_fenced', 'user_sync_outer_transaction_unsupported', 'user_sync_policy_stale', 'invalid_user_import_result', 'consumer_sync_import_conflict', 'consumer_import_email_conflict', 'consumer_import_password_unsupported', 'consumer_import_role_denied', 'consumer_import_metadata_denied', 'consumer_import_disabled', 'consumer_import_snapshot_unavailable', 'consumer_import_unavailable', 'consumer_sync_response_too_large', 'consumer_sync_disabled', 'consumer_sync_import_disabled'];

        return $error instanceof IdentityException && in_array($error->errorCode, $allowed, true) ? $error->errorCode : 'user_import_unavailable';
    }

    public function __serialize(): array
    {
        throw new \LogicException('Import runners cannot be queued.');
    }
}
