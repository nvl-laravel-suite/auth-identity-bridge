<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Consumer;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserSyncManager;
use IdentityPlatform\Laravel\Sync\UserSyncWorkRepository;
use Illuminate\Database\Eloquent\Builder;
use Throwable;

/** @api */
class CommandJournal
{
    public function __construct(private IdentityConfig $config, private UserSyncManager $sync, private UserSyncWorkRepository $work) {}

    public function retain(array $reference): ConsumerCommand
    {
        $this->validate($reference);
        // A surrounding domain transaction could roll back after the remote commit.
        Contract::require($this->model()->getConnection()->transactionLevel() === 0, 'recovery_unavailable', 503);

        return $this->model()->getConnection()->transaction(function () use ($reference) {
            $id = $this->id($reference);
            $row = $this->query()->createOrFirst(['id' => $id], ['binding_hash' => $this->config->bindingHash(), 'reference' => $reference]);
            Contract::require($row->reference === $reference, 'idempotency_conflict', 409);

            return $row;
        });
    }

    public function original(array $reference): ConsumerCommand
    {
        $this->validate($reference);
        $row = $this->query()->find($this->id($reference));
        Contract::require($row !== null && $row->reference === $reference, 'invalid_command_reference', 409);

        return $row;
    }

    public function state(array $reference, string $state): void
    {
        Contract::require(in_array($state, ['failed', 'unknown'], true), 'invalid_command_reference', 409);
        $row = $this->original($reference);
        // A late uncertain response can never erase independently confirmed commit truth.
        $this->query()->whereKey($row->id)->where('state', '!=', 'committed')->update(['state' => $state]);
    }

    public function forActor(IdentitySession $actor, string $key): array
    {
        $id = $this->id(['bindingHash' => $this->config->bindingHash(), 'subject' => $actor->subject, 'centralSessionId' => $actor->sid, 'organizationId' => $actor->selection['organizationId'] ?? null, 'roleId' => $actor->selection['roleId'] ?? null, 'idempotencyKey' => $key]);
        $row = $this->query()->find($id);
        Contract::require($row !== null, 'invalid_command_reference', 409);
        $this->validate($row->reference);
        Contract::require($row->reference['localSessionId'] === $actor->id && $row->reference['contextVersion'] === $actor->context_version, 'context_changed', 409);

        return $row->reference;
    }

    public function committed(array $reference, array $receipt): ConsumerCommand
    {
        ManagedContract::receipt($reference['operation'], $receipt, $reference);

        return $this->model()->getConnection()->transaction(function () use ($reference, $receipt) {
            $row = $this->query()->whereKey($this->original($reference)->id)->lockForUpdate()->firstOrFail();
            Contract::require($row->receipt === null || $row->receipt === $receipt, 'invalid_command_reference', 409);
            $row->update(['state' => 'committed', 'receipt' => $receipt]);

            return $row;
        });
    }

    /** Authorized background sync only; never queries human operation status or carries actor credentials. */
    public function refresh(string $id, bool $process = true): string
    {
        try {
            $row = $this->model()->getConnection()->transaction(function () use ($id) {
                $row = $this->query()->whereKey($id)->lockForUpdate()->firstOrFail();
                $this->validate($row->reference);
                Contract::require($row->state === 'committed' && is_array($row->receipt), 'invalid_command_reference', 409);
                ManagedContract::receipt($row->reference['operation'], $row->receipt, $row->reference);
                if ($this->config->value('sync.enabled', false) !== true) {
                    $row->update(['refresh' => $this->config->value('users.model') === null ? 'not_required' : 'not_configured']);
                } elseif ($row->sync_request_id === null) {
                    $row->update(['sync_request_id' => $this->sync->request($row->reference['userId']), 'refresh' => 'pending']);
                } elseif (in_array($row->refresh, ['not_required', 'not_configured'], true)) {
                    $row->update(['refresh' => 'pending']);
                }

                return $row;
            });
            if ($row->sync_request_id === null || in_array($row->refresh, ['refreshed', 'not_required', 'not_configured'], true) || ! $process) {
                return $row->refresh;
            }
            $this->sync->process($row->sync_request_id);
            $work = $this->work->find($row->sync_request_id);
            Contract::require($work !== null && $work->completed_generation >= $work->generation, 'recovery_unavailable', 503);
            $this->query()->whereKey($id)->update(['refresh' => 'refreshed']);

            return 'refreshed';
        } catch (Throwable) {
            // The committed journal is itself the durable intent if queue/work creation failed.
            return 'pending';
        }
    }

    /** Host schedulers may retry committed refresh intents; original ordinary authority is still required for unknown status. */
    public function pendingRefreshIds(int $limit = 100): array
    {
        Contract::require($limit >= 1 && $limit <= 100, 'validation_failed', 400);

        return $this->query()->where('state', 'committed')->whereIn('refresh', ['pending', 'not_configured'])->orderBy('id')->limit($limit)->pluck('id')->all();
    }

    public function validate(array $reference): void
    {
        Contract::require(Contract::keys($reference, ['contract', 'bindingHash', 'issuer', 'applicationId', 'clientId', 'localSessionId', 'subject', 'centralSessionId', 'organizationId', 'roleId', 'contextVersion', 'operation', 'userId', 'expectedVersion', 'idempotencyKey', 'changedFields'])
            && $reference['contract'] === 'platform-consumer-command-reference.v1'
            && $reference['bindingHash'] === $this->config->bindingHash() && $reference['issuer'] === $this->config->issuer()
            && $reference['applicationId'] === $this->config->applicationId() && $reference['clientId'] === $this->config->clientId()
            && in_array($reference['operation'], ManagedContract::WRITES, true)
            && ManagedContract::identifier($reference['localSessionId']) && ManagedContract::identifier($reference['subject']) && ManagedContract::identifier($reference['centralSessionId'])
            && ($reference['organizationId'] === null || ManagedContract::identifier($reference['organizationId'])) && ($reference['roleId'] === null || ManagedContract::identifier($reference['roleId']))
            && is_int($reference['contextVersion']) && $reference['contextVersion'] >= 0 && $reference['contextVersion'] <= 9007199254740991
            && ManagedContract::identifier($reference['userId']) && ManagedContract::version($reference['expectedVersion']) && $reference['expectedVersion'] < 9007199254740991
            && ManagedContract::key($reference['idempotencyKey']) && ManagedContract::fieldNames($reference['operation'], $reference['changedFields']), 'invalid_command_reference', 409);
    }

    private function id(array $reference): string
    {
        return hash('sha256', json_encode([$reference['bindingHash'], $reference['subject'], $reference['centralSessionId'], $reference['organizationId'], $reference['roleId'], $reference['idempotencyKey']], JSON_THROW_ON_ERROR));
    }

    private function model(): ConsumerCommand
    {
        return (new ConsumerCommand)->setConnection($this->config->value('connection'));
    }

    private function query(): Builder
    {
        return $this->model()->newQuery()->where('binding_hash', $this->config->bindingHash());
    }
}
