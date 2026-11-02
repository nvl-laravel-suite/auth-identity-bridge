<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use Closure;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Database\Eloquent\Builder;

class DelegatedActionRepository
{
    public function __construct(private IdentityConfig $config) {}

    /**
     * @return Builder<IdentityDelegatedAction>
     */
    public function query(): Builder
    {
        return IdentityDelegatedAction::query()->where('binding_hash', $this->config->bindingHash());
    }

    public function find(string $id, bool $lock = false): ?IdentityDelegatedAction
    {
        $query = $this->query()->whereKey($id);

        return ($lock ? $query->lockForUpdate() : $query)->first();
    }

    /**
     * @param  array<model-property<IdentityDelegatedAction>, mixed>  $values
     */
    public function create(array $values): IdentityDelegatedAction
    {
        return IdentityDelegatedAction::query()->create([...$values, 'binding_hash' => $this->config->bindingHash()]);
    }

    /**
     * @template TResult
     *
     * @param  Closure(): TResult  $work
     * @return TResult
     */
    public function transaction(Closure $work): mixed
    {
        return (new IdentityDelegatedAction)->getConnection()->transaction($work);
    }

    public function reported(string $id): void
    {
        $this->query()->whereKey($id)->whereNull('reported_at')->update(['reported_at' => now()]);
    }

    /** @return list<array<string, mixed>> */
    public function forPerson(string $centralSubject): array
    {
        $rows = $this->query()->where(fn (Builder $query) => $query->where('actor_id', $centralSubject)->orWhere('subject_id', $centralSubject))->latest()->limit(100)->get()->map(fn (IdentityDelegatedAction $action) => [
            'operation' => $action->operation, 'outcome' => $action->outcome, 'actor_id' => $action->actor_id,
            'subject_id' => $action->subject_id, 'organization_id' => $action->organization_id,
            'actor_name' => $action->audit['actor_name'] ?? '', 'subject_name' => $action->audit['subject_name'] ?? '',
            'resource_type' => $action->resource_type, 'resource_id' => $action->resource_id,
            'reason' => $action->audit['reason'], 'ticket_reference' => $action->audit['ticket_reference'],
            'created_at' => $action->created_at->toIso8601String(), 'reported_at' => $action->reported_at?->toIso8601String(),
        ])->all();

        return array_values($rows);
    }
}
