<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Models\IdentityModel;

/**
 * Persisted local state and native casts.
 *
 * @property string $id
 * @property int $policy_version
 * @property string|null $list_cursor
 * @property string|null $known_cursor
 * @property bool $list_exhausted
 * @property bool $known_exhausted
 * @property int|null $cycle_generation
 * @property int|null $cycle_policy_version
 * @property int $progress_version
 */
class UserSyncBinding extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'policy_version', 'list_cursor', 'known_cursor', 'list_exhausted', 'known_exhausted', 'cycle_generation', 'cycle_policy_version', 'progress_version'];

    protected $table = 'identity_user_sync_bindings';

    protected $attributes = ['list_exhausted' => false, 'known_exhausted' => false, 'progress_version' => 0];

    protected function casts(): array
    {
        return ['policy_version' => 'integer', 'list_exhausted' => 'boolean', 'known_exhausted' => 'boolean', 'cycle_generation' => 'integer', 'cycle_policy_version' => 'integer', 'progress_version' => 'integer'];
    }
}
