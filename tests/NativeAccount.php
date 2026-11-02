<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests;

use IdentityPlatform\Laravel\Users\HasIdentityAccess;
use Illuminate\Foundation\Auth\User;

class NativeAccount extends User
{
    use HasIdentityAccess;

    protected $table = 'native_accounts';

    protected $guarded = [];
}
