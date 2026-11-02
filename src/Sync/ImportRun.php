<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Models\IdentityModel;

/**
 * Persisted local state and native casts.
 *
 * @property string $id
 * @property string $binding_hash
 * @property string $consumer_name
 * @property string $source_name
 * @property string $source_class
 * @property int $batch_size
 * @property string|null $cursor
 * @property bool $exhausted
 * @property string $status
 * @property string|null $error_code
 * @property string $remote_status
 * @property int $accepted_in_last_attempt
 */
class ImportRun extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'consumer_name', 'source_name', 'source_class', 'batch_size', 'cursor', 'exhausted', 'status', 'error_code', 'remote_status', 'accepted_in_last_attempt'];

    protected $table = 'identity_import_runs';

    protected function casts(): array
    {
        return ['accepted_in_last_attempt' => 'integer', 'exhausted' => 'boolean', 'batch_size' => 'integer'];
    }
}
