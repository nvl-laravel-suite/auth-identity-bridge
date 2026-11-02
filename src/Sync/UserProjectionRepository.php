<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Users\ProjectionOwnership;

class UserProjectionRepository
{
    public function __construct(private IdentityConfig $config, private ProjectionOwnership $ownership) {}

    public function find(?string $id): ?IdentityUser
    {
        $user = $id ? IdentityUser::find($id) : null;

        return $user ? $this->present($user) : null;
    }

    public function synchronize(string $issuer, string $subject, array $profile): array
    {
        $identityKey = hash('sha256', $issuer."\0".$subject);

        return (new IdentityUser)->getConnection()->transaction(function () use ($identityKey, $issuer, $subject, $profile): array {
            $initial = IdentityUser::query()->createOrFirst(['identity_key' => $identityKey], ['issuer' => $issuer, 'subject' => $subject]);
            $created = $initial->wasRecentlyCreated;
            $user = IdentityUser::query()->whereKey($initial->getKey())->lockForUpdate()->firstOrFail();
            if ($user->issuer !== $issuer || $user->subject !== $subject) {
                throw new IdentityException('identity_projection_conflict');
            }
            if ($profile !== []) {
                $id = hash('sha256', $this->config->bindingHash()."\0".$issuer."\0".$subject);
                $state = UserSyncState::query()->createOrFirst(['id' => $id], ['binding_hash' => $this->config->bindingHash(), 'issuer' => $issuer, 'subject' => $subject, 'projection_id' => $user->id, 'state' => 'active']);
                $state = UserSyncState::query()->whereKey($id)->lockForUpdate()->firstOrFail();
                if ($state->version === 0) {
                    $facts = $state->jit_profile ?? [];
                    if (array_key_exists('email', $profile) && ($facts['email'] ?? null) !== $profile['email'] && ! array_key_exists('email_verified', $profile)) {
                        $profile['email_verified'] = false;
                    }
                    $state->update(['jit_profile' => array_replace($facts, $profile)]);
                    if ($this->ownership->common($user) && ! UserSyncState::query()->where('projection_id', $user->id)->where('version', '>', 0)->where('binding_hash', $this->config->bindingHash())->exists()) {
                        $user->fill([...$profile, 'synchronized_at' => now()])->save();
                    }
                }
            }

            return [$this->present($user), $created];
        });
    }

    public function applyAccepted(IdentityUser $projection, UserSyncState $state): void
    {
        if ($this->ownership->common($projection) && $state->profile !== null) {
            $stored = IdentityUser::query()->whereKey($projection->id)->lockForUpdate()->firstOrFail();
            $projection->setRawAttributes($stored->getAttributes(), true);
            $profile = $state->profile;
            $projection->forceFill(['name' => $profile['name'], 'email' => $profile['email'], 'email_verified' => $profile['emailVerified'], 'picture' => $profile['picture'], 'synchronized_at' => now()])->save();
        }
    }

    /** Binding presentation never borrows another application's mutable common facts. */
    public function present(IdentityUser $projection): IdentityUser
    {
        $state = UserSyncState::query()->where('binding_hash', $this->config->bindingHash())->where('projection_id', $projection->id)->first();
        $profile = $state?->version > 0 ? $state->profile : $state?->jit_profile;
        $copy = clone $projection;
        $copy->forceFill(['name' => $profile['name'] ?? null, 'email' => $profile['email'] ?? null, 'picture' => $profile['picture'] ?? null, 'email_verified' => $profile['emailVerified'] ?? $profile['email_verified'] ?? false]);
        $copy->syncOriginal();

        return $copy;
    }
}
