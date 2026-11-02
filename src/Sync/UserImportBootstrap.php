<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityUserLink;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\ExecutionPolicy;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Users\NativeOwner;
use IdentityPlatform\Laravel\Users\NativeUserMapper;
use IdentityPlatform\Laravel\Users\ProjectionOwnership;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Throwable;

class UserImportBootstrap
{
    public function __construct(private ConsumerGraph $graph, private IdentityConfig $config, private UserProjectionRepository $projections, private UserSnapshotRepository $snapshots, private NativeUserMapper $mapper) {}

    /** @param list<array{sourceUserId: string, nativeUserId: int|string}> $associations */
    public function associate(UserImportResult $result, array $associations): array
    {
        app(ExecutionPolicy::class)->assertOutboundAllowed();
        Contract::require($result->bindingHash === $this->config->bindingHash() && $result->issuer === $this->config->issuer()
            && $result->clientId === $this->config->clientId() && $result->applicationId === $this->config->applicationId(), 'user_import_binding_changed', 409);
        $model = $this->config->value('users.model');
        Contract::require(is_string($model) && is_subclass_of($model, Model::class) && is_subclass_of($model, Authenticatable::class), 'user_import_association_invalid', 422);
        $connection = (new IdentityUserLink)->getConnection();
        Contract::require((new $model)->getConnection()->getName() === $connection->getName(), 'identity_user_connection_mismatch', 503);
        Contract::require(array_is_list($associations) && count($associations) === count($result->mappings), 'user_import_association_invalid', 422);
        $sources = array_map(fn (UserImportMapping $mapping) => $mapping->sourceUserId, $result->mappings);
        $ids = [];
        foreach ($associations as $association) {
            Contract::require(is_array($association) && Contract::keys($association, ['sourceUserId', 'nativeUserId'])
                && is_string($association['sourceUserId']) && in_array($association['sourceUserId'], $sources, true)
                && ! array_key_exists($association['sourceUserId'], $ids)
                && (is_int($association['nativeUserId']) || is_string($association['nativeUserId'])) && (string) $association['nativeUserId'] !== '', 'user_import_association_invalid', 422);
            $ids[$association['sourceUserId']] = (string) $association['nativeUserId'];
        }
        Contract::require(count(array_unique($ids)) === count($ids), 'user_import_association_invalid', 422);
        Contract::require($connection->transactionLevel() === 0, 'user_sync_outer_transaction_unsupported', 409);
        $this->snapshots->acceptInactive(array_map(fn ($mapping) => $mapping->snapshot, $result->mappings));
        try {
            return $connection->transaction(function () use ($result, $ids, $model): array {
                $binding = UserSyncBinding::query()->createOrFirst(['id' => $result->bindingHash]);
                $binding = UserSyncBinding::query()->whereKey($binding->id)->lockForUpdate()->firstOrFail();
                Contract::require($result->policyVersion >= $binding->policy_version, 'user_sync_policy_stale', 409);
                $binding->update(['policy_version' => $result->policyVersion]);
                // Use the same binding -> native -> projection order as snapshot synchronization.
                $ordered = $ids;
                asort($ordered, SORT_STRING);
                $users = [];
                foreach ($ordered as $source => $id) {
                    $user = $model::query()->whereKey($id)->lockForUpdate()->first();
                    Contract::require($user !== null && (string) $user->getKey() === $id, 'user_import_association_invalid', 409);
                    $users[$source] = $user;
                }
                $results = [];
                foreach ($result->mappings as $mapping) {
                    $snapshot = $mapping->snapshot;
                    $user = $users[$mapping->sourceUserId];
                    $ownerKey = NativeOwner::key($user);
                    $importId = hash('sha256', $result->bindingHash."\0".$mapping->sourceUserId);
                    $import = UserImportLink::query()->whereKey($importId)->lockForUpdate()->first();
                    Contract::require(! $import || ($import->source_user_id === $mapping->sourceUserId && $import->issuer === $snapshot->issuer && $import->subject === $snapshot->subject && $import->owner_key === $ownerKey), 'user_import_association_conflict', 409);
                    [$projection] = $this->projections->synchronize($snapshot->issuer, $snapshot->subject, []);
                    $link = IdentityUserLink::query()->where('binding_hash', $result->bindingHash)->where('projection_id', $projection->id)->lockForUpdate()->first();
                    Contract::require(! $link || ($link->user_type === $model && $link->user_id === (string) $user->getKey() && $link->owner_key === $ownerKey), 'user_import_association_conflict', 409);
                    $this->graph->make(ProjectionOwnership::class)->native($user, $projection);
                    if (! $link) {
                        IdentityUserLink::query()->create(['id' => hash('sha256', $result->bindingHash."\0".$projection->id), 'binding_hash' => $result->bindingHash, 'projection_id' => $projection->id,
                            'user_type' => $model, 'user_id' => (string) $user->getKey(), 'owner_key' => $ownerKey]);
                    }
                    if (! $import) {
                        UserImportLink::query()->create(['id' => $importId, 'binding_hash' => $result->bindingHash, 'source_user_id' => $mapping->sourceUserId, 'issuer' => $snapshot->issuer,
                            'subject' => $snapshot->subject, 'projection_id' => $projection->id, 'owner_key' => $ownerKey]);
                    }
                    $results[] = $this->snapshots->applyAssociated($snapshot);
                    // A newly associated native record uses the accepted snapshot even if this import response is stale.
                    if ($this->graph->make(ProjectionOwnership::class)->native($user, $projection)) {
                        $this->mapper->synchronize($user, $this->projections->present($projection->refresh()));
                    }
                }

                return $results;
            });
        } catch (UniqueConstraintViolationException) {
            $this->snapshots->recordProjectionFailure(array_map(fn ($mapping) => $mapping->snapshot, $result->mappings));
            throw new IdentityException('user_import_association_conflict', 409);
        } catch (IdentityException $error) {
            $this->snapshots->recordProjectionFailure(array_map(fn ($mapping) => $mapping->snapshot, $result->mappings));
            if ($error->errorCode === 'identity_native_owner_conflict') {
                throw new IdentityException('user_import_association_conflict', 409);
            }
            throw $error;
        } catch (Throwable) {
            $this->snapshots->recordProjectionFailure(array_map(fn ($mapping) => $mapping->snapshot, $result->mappings));
            throw new IdentityException('user_import_association_unavailable', 503);
        }
    }
}
