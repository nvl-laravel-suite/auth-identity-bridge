<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Profiles;

use IdentityPlatform\Laravel\Models\IdentityModel;

class LocalProfile extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'owner_key', 'display_name', 'avatar', 'biography', 'locale', 'timezone', 'preferences', 'version'];

    protected $table = 'identity_local_profiles';

    protected $hidden = ['owner_key', 'binding_hash'];

    protected function casts(): array
    {
        return ['version' => 'integer', 'preferences' => 'array'];
    }
}
