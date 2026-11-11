<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;

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
    use MassPrunable;

    /** Events and logout tokens stop verifying within ten minutes of receipt; a day absorbs clock drift. */
    public const RETENTION_SECONDS = 86400;

    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'protocol', 'message_id', 'body_hash', 'received_at'];

    protected $table = 'identity_inbox';

    protected function casts(): array
    {
        return ['received_at' => 'immutable_datetime'];
    }

    /**
     * Receipts whose message can no longer pass its own freshness check, so no replay needs them.
     *
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        return static::query()->where('received_at', '<=', now()->subSeconds(self::RETENTION_SECONDS));
    }
}
