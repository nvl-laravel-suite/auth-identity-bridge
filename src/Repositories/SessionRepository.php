<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Repositories;

use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Database\Eloquent\Builder;

class SessionRepository
{
    public function __construct(private IdentityConfig $config) {}

    public function query(): Builder
    {
        return IdentitySession::where('binding_hash', $this->config->bindingHash());
    }

    public function find(?string $id, bool $lock = false): ?IdentitySession
    {
        if (! $id) {
            return null;
        }
        $query = $this->query();

        return ($lock ? $query->lockForUpdate() : $query)->find($id);
    }

    public function delete(string $id): bool
    {
        return $this->query()->whereKey($id)->delete() === 1;
    }

    public function create(array $data): IdentitySession
    {
        return IdentitySession::create($data + ['binding_hash' => $this->config->bindingHash()]);
    }

    public function publish(IdentitySession $row, array $values): bool
    {
        return $this->query()->whereKey($row->id)->where('context_version', $row->context_version)->where('token_generation', $row->token_generation)->update($values) === 1;
    }
}
