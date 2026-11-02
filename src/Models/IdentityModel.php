<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Models;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Database\Eloquent\Model;

abstract class IdentityModel extends Model
{
    public $incrementing = false;

    protected $keyType = 'string';

    public function getConnectionName(): ?string
    {
        $connection = config('identity.connection');
        if (! $connection) {
            return parent::getConnectionName();
        }
        if (! is_string($connection)) {
            throw new IdentityException('invalid_identity_configuration');
        }

        return $connection;
    }
}
