<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Models;

class IdentityInbox extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'protocol', 'message_id', 'body_hash', 'received_at'];

    protected $table = 'identity_inbox';

    protected function casts(): array
    {
        return ['received_at' => 'immutable_datetime'];
    }
}
