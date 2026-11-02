<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use Carbon\CarbonImmutable;
use IdentityPlatform\Laravel\Models\IdentityModel;

/**
 * Persisted local state and native casts.
 *
 * @phpstan-import-type Profile from UserSnapshot
 *
 * @property string $id
 * @property string $binding_hash
 * @property string $issuer
 * @property string $subject
 * @property string $projection_id
 * @property int $version
 * @property int $policy_version
 * @property string $state
 * @property string|null $digest
 * @property Profile|null $profile
 * @property CarbonImmutable|null $synchronized_at
 * @property int $native_version
 * @property string $native_status
 * @property string|null $native_error
 * @property array<string, mixed>|null $jit_profile
 */
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
