<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

final class NativeOwner
{
    public static function key(Authenticatable $owner): string
    {
        $identifier = $owner->getAuthIdentifier();
        if ((! is_string($identifier) && ! is_int($identifier)) || (string) $identifier === '' || ($owner instanceof Model && ! $owner->exists)) {
            throw new IdentityException('identity_user_invalid', 409);
        }

        $namespace = $owner instanceof Model ? $owner->getConnection()->getName()."\0".$owner->getTable() : '';

        return hash('sha256', $owner::class."\0".$namespace."\0".(string) $identifier);
    }
}
