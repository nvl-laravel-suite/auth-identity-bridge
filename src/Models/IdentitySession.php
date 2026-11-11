<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;

/**
 * @phpstan-import-type Snapshot from \IdentityPlatform\Laravel\Authorization\AuthorizationClient
 *
 * Persisted internal projection; never a permission grant.
 *
 * @property string $binding_hash
 * @property string|null $user_id
 * @property string $subject
 * @property string $sid
 * @property string $token_vault
 * @property array{selected?: bool, organizationId?: string|null, roleId?: string|null} $selection
 * @property Snapshot|null $snapshot
 * @property array<array-key, mixed>|null $application_context
 * @property int $context_version
 * @property int $token_generation
 * @property CarbonImmutable $started_at
 * @property CarbonImmutable $last_activity_at
 * @property CarbonImmutable $expires_at
 */
class IdentitySession extends IdentityModel
{
    use MassPrunable;

    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'user_id', 'subject', 'sid', 'token_vault', 'selection', 'snapshot', 'application_context', 'context_version', 'token_generation', 'started_at', 'last_activity_at', 'expires_at'];

    protected $table = 'identity_sessions';

    protected $hidden = ['token_vault', 'snapshot', 'application_context'];

    protected function casts(): array
    {
        return ['application_context' => 'array', 'selection' => 'array', 'snapshot' => 'array', 'context_version' => 'integer', 'token_generation' => 'integer', 'started_at' => 'immutable_datetime', 'last_activity_at' => 'immutable_datetime', 'expires_at' => 'immutable_datetime'];
    }

    /**
     * Sessions past the absolute deadline fixed at sign-in, which no refresh extends and every
     * consumer refuses. Idle expiry is per-consumer configuration, so it is left to that deadline.
     *
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        return static::query()->where('expires_at', '<=', now());
    }
}
