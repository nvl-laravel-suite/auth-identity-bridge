<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Models\IdentityUser;
use Illuminate\Contracts\Auth\Authenticatable;

/** @api */
interface NativeUserMapper
{
    public function synchronize(Authenticatable $user, IdentityUser $projection): void;
}
