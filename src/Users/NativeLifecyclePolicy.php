<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use Illuminate\Database\Eloquent\Model;

interface NativeLifecyclePolicy
{
    public function mayProvision(string $state): bool;

    public function assertMappable(Model $user, string $state): void;
}
