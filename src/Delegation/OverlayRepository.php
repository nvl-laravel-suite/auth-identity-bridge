<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Database\Eloquent\Builder;

class OverlayRepository
{
    public function __construct(private IdentityConfig $config) {}

    /**
     * @return Builder<IdentityDelegation>
     */
    public function query(): Builder
    {
        return IdentityDelegation::where('binding_hash', $this->config->bindingHash());
    }

    public function find(string $sessionId, bool $lock = false): ?IdentityDelegation
    {
        $query = $this->query()->whereKey($sessionId)->whereIn('status', ['pending', 'active']);

        return ($lock ? $query->lockForUpdate() : $query)->first();
    }

    /**
     * @param  array<string, mixed>  $values
     */
    public function save(string $sessionId, array $values): IdentityDelegation
    {
        return IdentityDelegation::updateOrCreate(['id' => $sessionId, 'binding_hash' => $this->config->bindingHash()], $values);
    }

    public function stop(string $sessionId): void
    {
        $this->query()->whereKey($sessionId)->update(['status' => 'stopped', 'handle_vault' => null]);
    }
}
