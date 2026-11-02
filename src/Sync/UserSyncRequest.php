<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Models\IdentityModel;

class UserSyncRequest extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'issuer', 'subject', 'kind', 'generation', 'completed_generation', 'attempts', 'last_error', 'next_attempt_at'];

    protected $table = 'identity_user_sync_requests';

    protected $attributes = ['generation' => 1, 'completed_generation' => 0, 'attempts' => 0, 'kind' => 'subject'];

    protected function casts(): array
    {
        return ['generation' => 'integer', 'completed_generation' => 'integer', 'attempts' => 'integer', 'next_attempt_at' => 'immutable_datetime'];
    }
}
