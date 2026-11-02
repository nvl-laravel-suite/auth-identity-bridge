<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Models;

use Carbon\CarbonImmutable;

/** Persisted internal projection; never a permission grant.
 *
 * @property string $binding_hash
 * @property string $protocol
 * @property string $message_id
 * @property string $body_hash
 * @property CarbonImmutable $received_at
 */
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
