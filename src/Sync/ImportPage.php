<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Models\IdentityModel;

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
