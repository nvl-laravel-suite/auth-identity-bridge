<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Models;

/** Persisted internal projection; never a permission grant.
 *
 * @property string $kind
 * @property string $writer_binding
 * @property int $epoch
 * @property string $identity_key
 * @property string|null $group_name
 */
class IdentityProjectionOwner extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'kind', 'writer_binding', 'epoch', 'identity_key', 'group_name'];

    protected $table = 'identity_projection_owners';

    protected function casts(): array
    {
        return ['epoch' => 'integer'];
    }
}
