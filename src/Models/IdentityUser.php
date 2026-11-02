<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Models;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

/** Persisted internal projection; never a permission grant.
 *
 * @property string $identity_key
 * @property string $issuer
 * @property string $subject
 * @property string|null $name
 * @property string|null $email
 * @property string|null $picture
 * @property bool $email_verified
 * @property CarbonImmutable|null $synchronized_at
 */
class IdentityUser extends IdentityModel implements AuthenticatableContract
{
    /** @var list<string> Explicit internal persistence fields; services own authority. */
    protected $fillable = ['id', 'identity_key', 'issuer', 'subject', 'name', 'email', 'picture', 'email_verified', 'synchronized_at'];

    use Authenticatable, HasUuids;

    protected $table = 'identity_users';

    protected $hidden = ['identity_key'];

    protected function casts(): array
    {
        return ['email_verified' => 'boolean', 'synchronized_at' => 'immutable_datetime'];
    }

    public function getAuthPasswordName(): string
    {
        return '';
    }

    public function getAuthPassword(): string
    {
        return '';
    }
}
