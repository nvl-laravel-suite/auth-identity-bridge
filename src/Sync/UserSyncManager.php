<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\ExecutionPolicy;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Support\Facades\Cache;
use Throwable;

/** @api */
class UserSyncManager
{
    public function __construct(private IdentityConfig $config, private UserSnapshotClient $client, private UserSnapshotRepository $snapshots, private UserSyncWorkRepository $work, private ImportCheckpointRepository $imports) {}

    public function request(string $subject): string
    {
        $this->enabled();
        Contract::require(Contract::identifier($subject), 'user_sync_subjects_invalid', 422);
        $row = $this->work->request($subject);
        $row->getConnection()->afterCommit(fn () => $this->dispatch($row->id));

        return $row->id;
    }

    public function process(string $requestId): void
    {
        $this->enabled();
        $row = $this->work->find($requestId);
        if (! $row || $row->completed_generation >= $row->generation) {
            return;
        }
        try {
            if ($row->kind === 'binding') {
                $result = $this->reconcile();
                if (! $result['completed']) {
                    throw new IdentityException('user_sync_page_pending', 409, 5);
                }

                return;
            }
            $batch = $this->client->read([$row->subject]);
            $outcomes = $this->snapshots->applyBatch($batch);
            if (count($batch->profiles) !== 1) {
                throw new IdentityException('user_sync_subject_missing', 409);
            }
            if (in_array('native_pending', $outcomes, true) || $this->snapshots->nativePending($row->subject) > 0) {
                throw new IdentityException('user_sync_native_pending', 409, 30);
            }
            $this->work->complete($row);
        } catch (IdentityException $error) {
            $this->work->failed($row, $error->errorCode, $error->retryAfter ?? 30);
            throw $error;
        } catch (Throwable) {
            $this->work->failed($row, 'user_sync_unavailable', 30);
            throw new IdentityException('user_sync_unavailable', 503);
        }
    }

    public function reconcile(int $limit = 100): array
    {
        $this->enabled();
        Contract::require($limit >= 1 && $limit <= 100, 'user_sync_limit_invalid', 422);
        $lock = Cache::store($this->config->value('lock_store'))->lock('identity-user-sync:'.$this->config->bindingHash(), 60);
        if (! $lock->get()) {
            throw new IdentityException('user_sync_busy', 409);
        }
        try {
            $bindingRequest = $this->work->bindingRequest();
            $binding = $this->work->prepareProgress($this->work->binding(), $bindingRequest, fn () => $this->requireLease($lock));
            $known = $binding->known_exhausted ? [] : $this->work->known($binding->known_cursor, $limit);
            $policyVersion = $binding->policy_version;
            $cyclePolicyVersion = $binding->cycle_policy_version ?: null;
            $moreKnown = count($known) > $limit;
            $known = array_slice($known, 0, $limit);
            $missing = 0;
            $nativePending = 0;
            $applied = 0;
            $stale = 0;
            if ($known !== []) {
                $batch = $this->client->read(array_map(fn ($row) => $row->subject, $known));
                $outcomes = $this->snapshots->applyBatch($batch);
                $policyVersion = $batch->policyVersion;
                $cyclePolicyVersion ??= $policyVersion;
                $applied += count(array_filter($outcomes, fn ($outcome) => in_array($outcome, ['applied', 'unchanged'], true)));
                $stale += count(array_filter($outcomes, fn ($outcome) => $outcome === 'stale'));
                $found = array_combine(array_map(fn ($snapshot) => $snapshot->subject, $batch->profiles), $outcomes);
                foreach ($known as $row) {
                    if (! isset($found[$row->subject])) {
                        if ($row->completed_generation >= $row->generation) {
                            $row = $this->work->request($row->subject);
                        }
                        $this->work->failed($row, 'user_sync_subject_missing', 30);
                        $missing++;

                        continue;
                    }
                    if ($found[$row->subject] === 'native_pending' || $this->snapshots->nativePending($row->subject) > 0) {
                        $this->work->failed($row, 'user_sync_native_pending', 30);
                        $nativePending++;

                        continue;
                    }
                    $this->work->complete($row);
                }
            }
            $listCursor = null;
            $profiles = 0;
            if (! $binding->list_exhausted) {
                try {
                    $batch = $this->client->listing($binding->list_cursor, $limit);
                } catch (IdentityException $error) {
                    if ($error->status !== 400 || $error->errorCode !== 'consumer_sync_cursor_invalid' || $binding->list_cursor === null) {
                        throw $error;
                    }
                    $binding = $this->work->restartList($binding, fn () => $this->requireLease($lock));
                    $batch = $this->client->listing(null, $limit);
                }
                $outcomes = $this->snapshots->applyBatch($batch);
                $applied += count(array_filter($outcomes, fn ($outcome) => in_array($outcome, ['applied', 'unchanged'], true)));
                $stale += count(array_filter($outcomes, fn ($outcome) => $outcome === 'stale'));
                foreach ($batch->profiles as $index => $snapshot) {
                    $registered = $this->work->register($snapshot->subject);
                    if ($outcomes[$index] === 'native_pending' || $this->snapshots->nativePending($snapshot->subject) > 0) {
                        if ($registered->completed_generation >= $registered->generation) {
                            $registered = $this->work->request($snapshot->subject);
                        }
                        $this->work->failed($registered, 'user_sync_native_pending', 30);
                        $nativePending++;

                        continue;
                    }
                    if ($registered->wasRecentlyCreated) {
                        $this->work->complete($registered);
                    }
                }
                $listCursor = $batch->nextCursor;
                $profiles = count($batch->profiles);
                $policyVersion = $batch->policyVersion;
                $cyclePolicyVersion ??= $policyVersion;
            }
            $knownCursor = $moreKnown ? end($known)->subject : null;
            $pending = $this->work->pendingCount();
            $nativePending = $this->snapshots->nativePending();
            $importCounts = $this->imports->bindingCounts();
            $restartCycle = $cyclePolicyVersion !== null && $cyclePolicyVersion !== $policyVersion;
            $completed = ! $restartCycle && $importCounts['unresolvedImports'] === 0 && $listCursor === null && $knownCursor === null && $pending === 0 && $missing === 0 && $nativePending === 0;
            $this->work->publishProgress($binding, $listCursor, $knownCursor, $bindingRequest, $policyVersion, $completed, fn () => $this->requireLease($lock), $listCursor === null, $knownCursor === null, $restartCycle);
            if ($restartCycle) {
                $listCursor = null;
                $knownCursor = null;
            }
            // Publication completes only the captured generation. Report any newer/current work afterward.
            $currentBindingRequest = $this->work->bindingRequest();
            $bindingPending = $currentBindingRequest && $currentBindingRequest->completed_generation < $currentBindingRequest->generation;
            $pending = $this->work->pendingCount() + ($bindingPending ? 1 : 0);
            $completed = $completed && $pending === 0;

            return [...$importCounts, 'applied' => $applied, 'stale' => $stale, 'failed' => $missing + $nativePending, 'profiles' => $profiles, 'known' => count($known), 'missing' => $missing, 'nativePending' => $nativePending, 'nextCursor' => $listCursor, 'knownCursor' => $knownCursor, 'pending' => $pending, 'completed' => $completed];
        } finally {
            $lock->release();
        }
    }

    private function dispatch(string $id): void
    {
        try {
            RefreshIdentityUser::dispatch($id)->afterCommit();
        } catch (Throwable) { /* Durable pending work is redispatched by reconciliation. */
        }
    }

    private function requireLease(object $lock): void
    {
        try {
            if ($lock->refresh(60)) {
                return;
            }
        } catch (Throwable) {
        }
        throw new IdentityException('user_sync_busy', 409);
    }

    public function requestBinding(): string
    {
        $this->enabled();
        $row = $this->work->bindingRequest(true);
        $row->getConnection()->afterCommit(fn () => $this->dispatch($row->id));

        return $row->id;
    }

    private function enabled(): void
    {
        app(ExecutionPolicy::class)->assertOutboundAllowed();
        Contract::require($this->config->value('sync.enabled', false) === true, 'user_sync_disabled', 404);
    }
}
