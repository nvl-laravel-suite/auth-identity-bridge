<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Profiles;

use IdentityPlatform\Laravel\Models\IdentityModel;

/**
 * Persisted local state and native casts.
 *
 * @property string $id
 * @property string $binding_hash
 * @property string $owner_key
 * @property string|null $display_name
 * @property string|null $avatar
 * @property string|null $biography
 * @property string|null $locale
 * @property string|null $timezone
 * @property array<array-key, mixed> $preferences
 * @property int $version
 */
class LocalProfile extends IdentityModel
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'owner_key', 'display_name', 'avatar', 'biography', 'locale', 'timezone', 'preferences', 'version'];

    protected $table = 'identity_local_profiles';

    protected $hidden = ['owner_key', 'binding_hash'];

    protected function casts(): array
    {
        return ['version' => 'integer', 'preferences' => 'array'];
    }
}
