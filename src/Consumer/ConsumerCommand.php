<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Consumer;

use Illuminate\Database\Eloquent\Model;

/**
 * Private nonsecret recovery journal. Repositories explicitly select the immutable consumer connection.
 *
 * @property string $id
 * @property string $binding_hash
 * @property array<array-key, mixed> $reference
 * @property string $state
 * @property array<array-key, mixed>|null $receipt
 * @property string $refresh
 * @property string|null $sync_request_id
 */
class ConsumerCommand extends Model
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'reference', 'state', 'receipt', 'refresh', 'sync_request_id'];

    protected $table = 'identity_consumer_commands';

    public $incrementing = false;

    protected $keyType = 'string';

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['reference' => 'array', 'receipt' => 'array'];
    }
}
