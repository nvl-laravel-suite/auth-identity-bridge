<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Models;

class IdentityProjectionOwner extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'kind', 'writer_binding', 'epoch', 'identity_key', 'group_name'];

    protected $table = 'identity_projection_owners';

    protected function casts(): array
    {
        return ['epoch' => 'integer'];
    }
}
