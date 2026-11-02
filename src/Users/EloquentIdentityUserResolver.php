<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Models\IdentityUserLink;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserProjectionRepository;
use IdentityPlatform\Laravel\Sync\UserSyncState;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Throwable;

class EloquentIdentityUserResolver implements IdentityUserResolver
{
    public function __construct(private ConsumerGraph $graph, private IdentityConfig $config, private NativeUserFactory $factory) {}

    public function resolve(IdentityUser $projection): Authenticatable
    {
        if (! $projection->exists || $projection->issuer !== $this->config->issuer()) {
            throw new IdentityException('identity_user_invalid', 409);
        }
        $state = UserSyncState::query()->where('binding_hash', $this->config->bindingHash())->where('projection_id', $projection->id)->first();
        if ($state && $state->state !== 'active') {
            throw new IdentityException('identity_user_inactive', 403);
        }
        $model = $this->config->value('users.model');
        if ($model === null) {
            return $this->graph->make(UserProjectionRepository::class)->present($projection);
        }
        if (! is_string($model) || ! is_subclass_of($model, Model::class) || ! is_subclass_of($model, Authenticatable::class) || ! $projection->exists || $projection->issuer !== $this->config->issuer()) {
            throw new IdentityException('identity_user_invalid', 409);
        }
        $connection = (new IdentityUserLink)->getConnection();
        if ((new $model)->getConnection()->getName() !== $connection->getName()) {
            throw new IdentityException('identity_user_connection_mismatch', 503);
        }
        $current = IdentityUser::query()->find($projection->id);
        if (! $current || $current->issuer !== $projection->issuer || $current->subject !== $projection->subject) {
            throw new IdentityException('identity_user_conflict', 409);
        }
        if ($linked = $this->graph->make(NativeUserRepository::class)->linked($current, false)) {
            $state = UserSyncState::query()->where('binding_hash', $this->config->bindingHash())->where('projection_id', $current->id)->first();
            if ($state && $state->state !== 'active') {
                throw new IdentityException('identity_user_inactive', 403);
            }

            return $linked;
        }
        try {
            return $connection->transaction(function () use ($projection, $model): Authenticatable {
                $locked = IdentityUser::query()->whereKey($projection->getKey())->lockForUpdate()->first();
                if (! $locked || $locked->issuer !== $projection->issuer || $locked->subject !== $projection->subject) {
                    throw new IdentityException('identity_user_conflict', 409);
                }
                $state = UserSyncState::query()->where('binding_hash', $this->config->bindingHash())->where('projection_id', $locked->id)->first();
                if ($state && $state->state !== 'active') {
                    throw new IdentityException('identity_user_inactive', 403);
                }
                $link = IdentityUserLink::query()->where('binding_hash', $this->config->bindingHash())->where('projection_id', $locked->id)->first();
                if ($link) {
                    $user = $link->user_type === $model ? $model::query()->find($link->user_id) : null;
                    if (! $user || NativeOwner::key($user) !== $link->owner_key) {
                        throw new IdentityException('identity_user_conflict', 409);
                    }

                    return $user;
                }
                $group = $this->config->value('users.native_group');
                if ($group !== null && $group['writer'] !== $this->config->context()->name()) {
                    throw new IdentityException('identity_native_writer_required', 409);
                }
                $policy = $this->config->value('users.lifecycle_policy', RetainedNativeLifecycle::class);
                if (! (new $policy)->mayProvision($state?->state ?? 'active')) {
                    throw new IdentityException('identity_user_provisioning_denied', 409);
                }
                // Observe this factory invocation, not a stale wasRecentlyCreated flag on a supplied row.
                $created = [];
                $events = Model::getEventDispatcher();
                $factoryEvents = clone $events;
                $factoryEvents->listen('eloquent.created: '.$model, function ($createdUser) use (&$created): void {
                    $created[] = (string) $createdUser->getKey();
                });
                Model::setEventDispatcher($factoryEvents);
                try {
                    $user = $this->factory->create($this->graph->make(UserProjectionRepository::class)->present($locked));
                } finally {
                    Model::setEventDispatcher($events);
                }

                if (! $user instanceof $model || ! $user->exists || ! $user->wasRecentlyCreated || ! in_array((string) $user->getKey(), $created, true) || $user->getConnection()->getName() !== $locked->getConnection()->getName()) {
                    throw new IdentityException('identity_user_invalid', 409);
                }
                $this->graph->make(ProjectionOwnership::class)->native($user, $locked, true);
                IdentityUserLink::query()->create([
                    'id' => hash('sha256', $this->config->bindingHash()."\0".$locked->id),
                    'binding_hash' => $this->config->bindingHash(), 'projection_id' => $locked->id,
                    'user_type' => $model, 'user_id' => (string) $user->getKey(), 'owner_key' => NativeOwner::key($user),
                ]);
                $this->graph->make(NativeUserMapper::class)->synchronize($user, $this->graph->make(UserProjectionRepository::class)->present($locked));

                return $user;
            });
        } catch (UniqueConstraintViolationException) {
            throw new IdentityException('identity_user_conflict', 409);
        } catch (IdentityException $error) {
            throw $error;
        } catch (Throwable) {
            throw new IdentityException('identity_user_unavailable', 503);
        }
    }
}
