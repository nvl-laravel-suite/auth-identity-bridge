<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use Carbon\CarbonImmutable;
use IdentityPlatform\Laravel\Models\IdentityModel;

/**
 * Source-bound pending or active delegation overlay.
 *
 * @property string $binding_hash
 * @property string $source_sid
 * @property string $status
 * @property string $browser_binding
 * @property int $context_version
 * @property string|null $handle_vault
 *
 * @phpstan-import-type DecisionData from DelegationDecision
 *
 * @phpstan-type PendingDecision array{subject: array{id: string}, organizationId: string|null, roleId: mixed, operations: non-empty-list<non-empty-string>}
 *
 * @property DecisionData|PendingDecision|null $decision
 * @property CarbonImmutable $expires_at
 */
class IdentityDelegation extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'source_sid', 'status', 'browser_binding', 'context_version', 'handle_vault', 'decision', 'expires_at'];

    protected $table = 'identity_delegations';

    protected $hidden = ['handle_vault', 'browser_binding'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['decision' => 'array', 'context_version' => 'integer', 'expires_at' => 'immutable_datetime'];
    }
}
