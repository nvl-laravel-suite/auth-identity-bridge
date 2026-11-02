<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use Illuminate\Database\Eloquent\Model;

/** Controlled cutover: retain existing mappings while refusing JIT/worker native creation. */
final class ExistingNativeOnlyLifecycle implements NativeLifecyclePolicy
{
    public function mayProvision(string $state): bool
    {
        return false;
    }

    public function assertMappable(Model $user, string $state): void
    {
        (new RetainedNativeLifecycle)->assertMappable($user, $state);
    }
}
