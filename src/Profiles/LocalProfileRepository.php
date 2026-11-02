<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Profiles;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Users\NativeOwner;
use Illuminate\Contracts\Auth\Authenticatable;

/** Persistence only: callers must establish current owner or management authority before writing. */
class LocalProfileRepository
{
    public function __construct(private IdentityConfig $config) {}

    public function read(Authenticatable $owner): LocalProfile
    {
        $ownerKey = NativeOwner::key($owner);
        $binding = $this->config->bindingHash();

        return LocalProfile::query()->createOrFirst(['id' => hash('sha256', $binding."\0".$ownerKey)], ['binding_hash' => $binding, 'owner_key' => $ownerKey, 'preferences' => [], 'version' => 1]);
    }

    public function update(Authenticatable $owner, int $expectedVersion, array $fields): LocalProfile
    {
        $limits = ['display_name' => 255, 'avatar' => 2048, 'biography' => 5000, 'locale' => 35, 'timezone' => 100];
        if ($expectedVersion < 1 || $fields === [] || array_diff(array_keys($fields), [...array_keys($limits), 'preferences'])) {
            throw new IdentityException('profile_invalid', 422);
        }
        foreach ($fields as $key => $value) {
            if ($key === 'preferences') {
                if (! is_array($value) || strlen(json_encode($value, JSON_THROW_ON_ERROR)) > 16384) {
                    throw new IdentityException('profile_invalid', 422);
                }
            } elseif ($value !== null && (! is_string($value) || ! mb_check_encoding($value, 'UTF-8') || mb_strlen($value) > $limits[$key] || str_contains($value, "\0"))) {
                throw new IdentityException('profile_invalid', 422);
            }
        }
        $profile = $this->read($owner);
        $values = $fields;
        if (array_key_exists('preferences', $values)) {
            $values['preferences'] = json_encode($values['preferences'], JSON_THROW_ON_ERROR);
        }
        if (LocalProfile::query()->whereKey($profile->id)->where('binding_hash', $this->config->bindingHash())->where('owner_key', NativeOwner::key($owner))->where('version', $expectedVersion)->update([...$values, 'version' => $expectedVersion + 1, 'updated_at' => now()]) !== 1) {
            throw new IdentityException('profile_changed', 409);
        }

        return $profile->refresh();
    }

    public function lock(Authenticatable $owner): LocalProfile
    {
        $profile = $this->read($owner);

        return LocalProfile::query()->whereKey($profile->id)->where('binding_hash', $this->config->bindingHash())->where('owner_key', NativeOwner::key($owner))->lockForUpdate()->firstOrFail();
    }
}
