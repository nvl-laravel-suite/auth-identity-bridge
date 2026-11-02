<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use Carbon\CarbonImmutable;
use IdentityPlatform\Laravel\Models\IdentityModel;

/**
 * Persisted local state and native casts.
 *
 * @property string $id
 * @property string $binding_hash
 * @property string $issuer
 * @property string $subject
 * @property string $kind
 * @property int $generation
 * @property int $completed_generation
 * @property int $attempts
 * @property string|null $last_error
 * @property CarbonImmutable|null $next_attempt_at
 */
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
