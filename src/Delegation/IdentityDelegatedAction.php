<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use IdentityPlatform\Laravel\Models\IdentityModel;

/**
 * Immutable delegated mutation audit and reporting outbox.
 *
 * @property string $binding_hash
 * @property string $session_id
 * @property string $delegation_id
 * @property string $operation
 * @property string $command_digest
 * @property string $receipt_vault
 * @property string $outcome
 * @property array<array-key, mixed>|null $result
 * @property CarbonImmutable|null $reported_at
 * @property string $actor_id
 * @property string $subject_id
 * @property string|null $organization_id
 * @property string $resource_type
 * @property string $resource_id
 * @property array{actor_id: string, actor_name: string, subject_id: string, subject_name: string, organization_id: mixed, source_sid: string, versions: array<array-key, mixed>, reason: string, ticket_reference: string, admitted_at: mixed, reporting_expires_at: mixed} $audit
 * @property Carbon $created_at
 */
class IdentityDelegatedAction extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'session_id', 'delegation_id', 'operation', 'command_digest', 'receipt_vault', 'outcome', 'result', 'reported_at', 'actor_id', 'subject_id', 'organization_id', 'resource_type', 'resource_id', 'audit'];

    protected $table = 'identity_delegated_actions';

    protected $hidden = ['receipt_vault', 'binding_hash', 'session_id'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['result' => 'array', 'audit' => 'array', 'reported_at' => 'immutable_datetime'];
    }
}
