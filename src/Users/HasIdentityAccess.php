<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Authorization\IdentityAccess;

trait HasIdentityAccess
{
    public function identityAccess(): IdentityAccess
    {
        $access = app(IdentityAccess::class);
        $access->assertOwner($this);

        return $access;
    }
}
