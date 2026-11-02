<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Contracts\Auth\Authenticatable;

class EloquentNativeUserFactory implements NativeUserFactory
{
    public function __construct(private IdentityConfig $config) {}

    public function create(IdentityUser $projection): Authenticatable
    {
        $class = $this->config->value('users.model');
        Contract::require($class !== null, 'identity_user_invalid', 409);
        $user = new $class;
        $user->forceFill((new EloquentNativeUserMapper($this->config))->attributes($user, $projection));
        $user->save();

        return $user;
    }
}
