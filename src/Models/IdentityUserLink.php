<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Models;

class IdentityUserLink extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'projection_id', 'user_type', 'user_id', 'owner_key'];

    protected $table = 'identity_user_links';

    protected $hidden = ['owner_key'];
}
