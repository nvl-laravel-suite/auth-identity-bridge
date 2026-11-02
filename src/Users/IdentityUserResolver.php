<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Models\IdentityUser;
use Illuminate\Contracts\Auth\Authenticatable;

interface IdentityUserResolver
{
    public function resolve(IdentityUser $projection): Authenticatable;
}
