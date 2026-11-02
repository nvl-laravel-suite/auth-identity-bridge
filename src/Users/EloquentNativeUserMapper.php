<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\AvatarUrl;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserSyncBinding;
use IdentityPlatform\Laravel\Sync\UserSyncState;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

class EloquentNativeUserMapper implements NativeUserMapper
{
    public function __construct(private IdentityConfig $config) {}

    public function synchronize(Authenticatable $user, IdentityUser $projection): void
    {
        Contract::require($user instanceof Model && $user->getConnection()->getName() === $projection->getConnection()->getName(), 'identity_user_connection_mismatch', 503);
        $standalone = $user->getConnection()->transactionLevel() === 0;
        $user->getConnection()->transaction(function () use ($user, $projection, $standalone): void {
            if ($standalone) {
                $binding = UserSyncBinding::query()->createOrFirst(['id' => $this->config->bindingHash()]);
                UserSyncBinding::query()->whereKey($binding->id)->lockForUpdate()->firstOrFail();
            }
            $native = $user->newQuery()->whereKey($user->getKey())->lockForUpdate()->first();
            Contract::require($native !== null, 'identity_user_conflict', 409);
            $current = IdentityUser::query()->whereKey($projection->id)->lockForUpdate()->firstOrFail();
            $ownership = new ProjectionOwnership($this->config, app(ConsumerRegistry::class));
            if (! $ownership->native($native, $current)) {
                return;
            }
            $native->forceFill($this->attributes($native, $current));
            if ($native->isDirty()) {
                $native->save();
            }
            $user->setRawAttributes($native->getAttributes(), true);
        });
    }

    public function attributes(Model $user, IdentityUser $projection): array
    {
        $state = UserSyncState::query()->where('binding_hash', $this->config->bindingHash())->where('projection_id', $projection->id)->first();
        $profile = $state?->version > 0 ? $state->profile : $state?->jit_profile;
        $profile = is_array($profile) ? $profile : null;
        $policy = $this->config->value('users.lifecycle_policy', RetainedNativeLifecycle::class);
        (new $policy)->assertMappable($user, $state?->state ?? 'active');
        $definition = new NativeMappingDefinition($this->config->value('users'), $user);
        $facts = $profile ?? [];
        if (array_key_exists('email_verified', $facts)) {
            $facts['emailVerified'] = $facts['email_verified'];
        }
        $facts['state'] = $state?->state ?? 'active';
        if ($state?->version > 0 || array_key_exists('picture', $facts)) {
            $facts['picture'] = AvatarUrl::safe($profile['picture'] ?? null);
        }
        if (isset($definition->fields['email_verified_at'])) {
            $verified = $definition->fields['email_verified_at']['column'];
            $email = $definition->fields['email']['column'];
            $facts['email_verified_at'] = ($profile['emailVerified'] ?? $profile['email_verified'] ?? false) ? (($user->getAttribute($email) === ($profile['email'] ?? null) && $user->getAttribute($verified) !== null) ? $user->getAttribute($verified) : now()) : null;
        }
        // Tombstones redact protected metadata; ordinary absent JIT facts remain omitted.
        if ($state?->version > 0 && $profile === null) {
            $facts += ['adminNotes' => null, 'tags' => [], 'lastLoginAt' => null];
        }

        return $definition->values($facts, $user);
    }
}
