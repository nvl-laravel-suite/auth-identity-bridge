<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Models\IdentityModel;

/**
 * Persisted local state and native casts.
 *
 * @property string $id
 * @property string $run_id
 * @property string $page_id
 * @property string $import_binding_id
 * @property int $position
 * @property string $outcome
 */
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
