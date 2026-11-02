<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Models\IdentityModel;

class UserSyncState extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'issuer', 'subject', 'projection_id', 'version', 'policy_version', 'state', 'digest', 'profile', 'synchronized_at', 'native_version', 'native_status', 'native_error', 'jit_profile'];

    protected $table = 'identity_user_sync_states';

    protected function casts(): array
    {
        return ['native_version' => 'integer', 'jit_profile' => 'array', 'version' => 'integer', 'policy_version' => 'integer', 'profile' => 'array', 'synchronized_at' => 'immutable_datetime'];
    }
}
