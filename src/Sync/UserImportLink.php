<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Models\IdentityModel;

/**
 * Persisted local state and native casts.
 *
 * @property string $id
 * @property string $binding_hash
 * @property string $source_user_id
 * @property string $issuer
 * @property string $subject
 * @property string $projection_id
 * @property string $owner_key
 */
class UserImportLink extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'source_user_id', 'issuer', 'subject', 'projection_id', 'owner_key'];

    protected $table = 'identity_user_import_links';
}
