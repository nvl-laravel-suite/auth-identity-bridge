<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Models\IdentityUserLink;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

class NativeUserRepository
{
    public function __construct(private IdentityConfig $config) {}

    /** @return (Authenticatable&Model)|null */
    public function linked(IdentityUser $projection, bool $lock = true): ?Authenticatable
    {
        $model = $this->config->value('users.model');
        if ($model === null) {
            return null;
        }
        $link = IdentityUserLink::query()->where('binding_hash', $this->config->bindingHash())->where('projection_id', $projection->id)->first();
        if (! $link) {
            return null;
        }
        $query = $link->user_type === $model ? $model::query()->whereKey($link->user_id) : null;
        $user = $query ? ($lock ? $query->lockForUpdate() : $query)->first() : null;
        if (! $user instanceof Authenticatable || NativeOwner::key($user) !== $link->owner_key) {
            throw new IdentityException('identity_user_conflict', 409);
        }

        return $user;
    }
}
