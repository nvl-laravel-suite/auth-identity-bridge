<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Models\IdentityModel;

class ImportEntry extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'run_id', 'page_id', 'import_binding_id', 'position', 'outcome'];

    protected $table = 'identity_import_entries';

    protected function casts(): array
    {
        return ['position' => 'integer'];
    }
}
