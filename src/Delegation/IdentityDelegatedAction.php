<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use IdentityPlatform\Laravel\Models\IdentityModel;

class IdentityDelegatedAction extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'session_id', 'delegation_id', 'operation', 'command_digest', 'receipt_vault', 'outcome', 'result', 'reported_at', 'actor_id', 'subject_id', 'organization_id', 'resource_type', 'resource_id', 'audit'];

    protected $table = 'identity_delegated_actions';

    protected $hidden = ['receipt_vault', 'binding_hash', 'session_id'];

    protected function casts(): array
    {
        return ['result' => 'array', 'audit' => 'array', 'reported_at' => 'immutable_datetime'];
    }
}
