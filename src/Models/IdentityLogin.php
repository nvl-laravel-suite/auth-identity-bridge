<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;

/** Persisted internal projection; never a permission grant.
 *
 * @property string $binding_hash
 * @property string $browser_hash
 * @property string $intent
 * @property string $protocol
 * @property CarbonImmutable $expires_at
 */
class IdentityLogin extends IdentityModel
{
    use MassPrunable;

    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'binding_hash', 'browser_hash', 'intent', 'protocol', 'expires_at'];

    protected $table = 'identity_logins';

    protected $hidden = ['intent', 'browser_hash'];

    protected function casts(): array
    {
        return ['expires_at' => 'immutable_datetime'];
    }

    /**
     * Abandoned transactions past their deadline; redemption already refuses them.
     *
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        return static::query()->where('expires_at', '<=', now());
    }
}
