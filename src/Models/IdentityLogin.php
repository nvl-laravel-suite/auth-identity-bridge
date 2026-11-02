<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Models;

class IdentityLogin extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'browser_hash', 'intent', 'protocol', 'expires_at'];

    protected $table = 'identity_logins';

    protected $hidden = ['intent', 'browser_hash'];

    protected function casts(): array
    {
        return ['expires_at' => 'immutable_datetime'];
    }
}
