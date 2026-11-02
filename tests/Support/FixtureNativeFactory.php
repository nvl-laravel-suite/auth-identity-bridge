<?php

namespace IdentityPlatform\Laravel\Tests\Support;

use Closure;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Users\NativeUserFactory;
use Illuminate\Contracts\Auth\Authenticatable;

/** Registered class adapter for fault injection; closures never enter cached configuration. */
final class FixtureNativeFactory implements NativeUserFactory
{
    public static Closure $create;

    public function create(IdentityUser $projection): Authenticatable
    {
        return (self::$create)($projection);
    }
}
