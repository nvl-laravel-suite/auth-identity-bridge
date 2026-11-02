<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Models\IdentityModel;

/**
 * Persisted local state and native casts.
 *
 * @property string $id
 * @property string $binding_hash
 * @property string $source_name
 * @property string $source_user_id
 * @property string $native_user_id
 * @property string $native_type
 * @property string $physical_key
 * @property string|null $subject
 * @property bool $associated
 * @property string $status
 */
class ImportBinding extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'source_name', 'source_user_id', 'native_user_id', 'native_type', 'physical_key', 'subject', 'associated', 'status'];

    protected $table = 'identity_import_bindings';

    protected function casts(): array
    {
        return ['associated' => 'boolean'];
    }
}
