<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Models\IdentityModel;

/**
 * Persisted local state and native casts.
 *
 * @property string $id
 * @property string $run_id
 * @property string|null $next_cursor
 * @property bool $finished
 */
class ImportPage extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'run_id', 'next_cursor', 'finished'];

    protected $table = 'identity_import_pages';

    protected function casts(): array
    {
        return ['finished' => 'boolean'];
    }
}
