<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Authorization\Contract;
use Illuminate\Database\Eloquent\Model;

final class RetainedNativeLifecycle implements NativeLifecyclePolicy
{
    public function mayProvision(string $state): bool
    {
        return $state === 'active';
    }

    public function assertMappable(Model $user, string $state): void
    {
        Contract::require(! method_exists($user, 'trashed') || ! $user->trashed(), 'identity_user_soft_deleted', 409);
    }
}
