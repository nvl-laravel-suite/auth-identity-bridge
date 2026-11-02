<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use IdentityPlatform\Laravel\Models\IdentityModel;

class IdentityDelegation extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'source_sid', 'status', 'browser_binding', 'context_version', 'handle_vault', 'decision', 'expires_at'];

    protected $table = 'identity_delegations';

    protected $hidden = ['handle_vault', 'browser_binding'];

    protected function casts(): array
    {
        return ['decision' => 'array', 'context_version' => 'integer', 'expires_at' => 'immutable_datetime'];
    }
}
