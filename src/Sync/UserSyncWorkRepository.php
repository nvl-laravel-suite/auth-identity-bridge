<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Database\Eloquent\Builder;

class UserSyncWorkRepository
{
    public function __construct(private IdentityConfig $config) {}

    public function register(string $subject): UserSyncRequest
    {
        $binding = $this->config->bindingHash();
        $issuer = $this->config->issuer();

        return UserSyncRequest::query()->createOrFirst(['id' => hash('sha256', $binding."\0".$issuer."\0".$subject)], ['binding_hash' => $binding, 'issuer' => $issuer, 'subject' => $subject]);
    }

    public function request(string $subject): UserSyncRequest
    {
        $row = $this->register($subject);
        if (! $row->wasRecentlyCreated) {
            $this->query()->whereKey($row->id)->increment('generation', 1, ['next_attempt_at' => null]);
        }

        return $this->query()->where('issuer', $this->config->issuer())->whereKey($row->id)->firstOrFail();
    }

    /** @return ($create is true ? UserSyncRequest : UserSyncRequest|null) */
    public function bindingRequest(bool $create = false): ?UserSyncRequest
    {
        $id = hash('sha256', $this->config->bindingHash()."\0binding-reconcile");
        if (! $create) {
            return $this->find($id);
        }
        $row = UserSyncRequest::query()->createOrFirst(['id' => $id], ['binding_hash' => $this->config->bindingHash(), 'issuer' => $this->config->issuer(), 'subject' => '', 'kind' => 'binding']);
        if (! $row->wasRecentlyCreated) {
            $this->query()->whereKey($id)->increment('generation', 1, ['next_attempt_at' => null]);
        }

        return $this->query()->where('issuer', $this->config->issuer())->whereKey($id)->firstOrFail();
    }

    public function find(string $id): ?UserSyncRequest
    {
        return $this->query()->where('issuer', $this->config->issuer())->find($id);
    }

    public function complete(UserSyncRequest $row): void
    {
        $this->query()->whereKey($row->id)->where('generation', $row->generation)->update(['completed_generation' => $row->generation, 'attempts' => 0, 'last_error' => null, 'next_attempt_at' => null]);
    }

    public function failed(UserSyncRequest $row, string $code, int $delay): void
    {
        $this->query()->whereKey($row->id)->where('generation', $row->generation)->whereColumn('completed_generation', '<', 'generation')->increment('attempts', 1, ['last_error' => $code, 'next_attempt_at' => now()->addSeconds($delay)]);
    }

    /**
     * @return array<int, UserSyncRequest>
     */
    public function pending(int $limit): array
    {
        return $this->query()->whereColumn('completed_generation', '<', 'generation')->where(fn ($q) => $q->whereNull('next_attempt_at')->orWhere('next_attempt_at', '<=', now()))->orderBy('id')->limit($limit)->get()->all();
    }

    public function pendingCount(): int
    {
        return $this->query()->where('kind', 'subject')->whereColumn('completed_generation', '<', 'generation')->count();
    }

    public function prepareProgress(UserSyncBinding $expected, ?UserSyncRequest $bindingRequest, \Closure $requireLease): UserSyncBinding
    {
        return (new UserSyncBinding)->getConnection()->transaction(function () use ($expected, $bindingRequest, $requireLease): UserSyncBinding {
            $current = UserSyncBinding::query()->whereKey($this->config->bindingHash())->lockForUpdate()->firstOrFail();
            $this->requireProgress($current, $expected);
            $generation = $bindingRequest !== null ? $bindingRequest->generation : 0;
            if ($current->cycle_generation !== $generation || $current->cycle_policy_version !== $current->policy_version) {
                $requireLease();
                // Unknown legacy coverage or a newer invalidation needs a fresh bounded traversal.
                $current->update(['list_cursor' => null, 'known_cursor' => null, 'list_exhausted' => false, 'known_exhausted' => false, 'cycle_generation' => $generation, 'cycle_policy_version' => $current->policy_version, 'progress_version' => $current->progress_version + 1]);
            }

            return $current;
        });
    }

    public function restartList(UserSyncBinding $expected, \Closure $requireLease): UserSyncBinding
    {
        return (new UserSyncBinding)->getConnection()->transaction(function () use ($expected, $requireLease): UserSyncBinding {
            $current = UserSyncBinding::query()->whereKey($this->config->bindingHash())->lockForUpdate()->firstOrFail();
            $this->requireProgress($current, $expected);
            $requireLease();
            $current->update(['list_cursor' => null, 'list_exhausted' => false, 'progress_version' => $current->progress_version + 1]);

            return $current;
        });
    }

    /**
     * @return array<int, UserSyncRequest>
     */
    public function known(?string $cursor, int $limit): array
    {
        return $this->query()->where('kind', 'subject')->when($cursor !== null, fn ($q) => $q->where('subject', '>', $cursor))->orderBy('subject')->limit($limit + 1)->get()->all();
    }

    public function binding(): UserSyncBinding
    {
        return UserSyncBinding::query()->createOrFirst(['id' => $this->config->bindingHash()]);
    }

    public function publishProgress(UserSyncBinding $expected, ?string $list, ?string $known, ?UserSyncRequest $bindingRequest, int $policyVersion, bool $completed, \Closure $requireLease, bool $listExhausted = false, bool $knownExhausted = false, bool $restartCycle = false): void
    {
        (new UserSyncBinding)->getConnection()->transaction(function () use ($expected, $list, $known, $bindingRequest, $policyVersion, $completed, $requireLease, $listExhausted, $knownExhausted, $restartCycle): void {
            $current = UserSyncBinding::query()->whereKey($this->config->bindingHash())->lockForUpdate()->firstOrFail();
            $this->requireProgress($current, $expected);
            Contract::require($current->policy_version <= $policyVersion, 'user_sync_policy_stale', 409);
            $requireLease();
            // End each traversal together; unresolved work is retried in the next bounded cycle.
            $cycleExhausted = ($listExhausted && $knownExhausted) || $restartCycle;
            $current->update(['list_cursor' => $restartCycle ? null : $list, 'known_cursor' => $restartCycle ? null : $known, 'list_exhausted' => $listExhausted && ! $cycleExhausted, 'known_exhausted' => $knownExhausted && ! $cycleExhausted, 'cycle_policy_version' => $policyVersion, 'progress_version' => $current->progress_version + 1]);
            if ($completed && ! $restartCycle && $bindingRequest) {
                $this->complete($bindingRequest);
            }
        });
    }

    private function requireProgress(UserSyncBinding $current, UserSyncBinding $expected): void
    {
        Contract::require($current->progress_version === $expected->progress_version
            && $current->list_cursor === $expected->list_cursor && $current->known_cursor === $expected->known_cursor
            && $current->list_exhausted === $expected->list_exhausted && $current->known_exhausted === $expected->known_exhausted
            && $current->cycle_generation === $expected->cycle_generation && $current->cycle_policy_version === $expected->cycle_policy_version,
            'user_sync_cursor_changed', 409);
    }

    /**
     * @return Builder<UserSyncRequest>
     */
    private function query(): Builder
    {
        return UserSyncRequest::query()->where('binding_hash', $this->config->bindingHash());
    }
}
