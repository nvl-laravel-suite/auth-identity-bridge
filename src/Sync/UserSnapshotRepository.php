<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use IdentityPlatform\Laravel\Users\NativeUserMapper;
use IdentityPlatform\Laravel\Users\NativeUserRepository;
use IdentityPlatform\Laravel\Users\ProjectionOwnership;
use Throwable;

class UserSnapshotRepository
{
    public function __construct(private ConsumerGraph $graph, private IdentityConfig $config, private UserProjectionRepository $projections, private NativeUserRepository $users, private NativeUserMapper $mapper) {}

    public function applyBatch(UserSnapshotBatch $batch): array
    {
        Contract::require($batch->bindingHash === $this->config->bindingHash(), 'user_sync_binding_changed', 409);
        $this->acceptInactive($batch->profiles);
        $this->refreshAcceptedPolicies($batch->profiles);
        try {
            return (new UserSyncBinding)->getConnection()->transaction(function () use ($batch): array {
                $this->binding($batch->policyVersion, true);
                $results = [];
                foreach ($batch->profiles as $snapshot) {
                    $results[] = $this->applyLocked($snapshot);
                }

                return $results;
            });
        } catch (Throwable $error) {
            if ($error instanceof IdentityException && in_array($error->errorCode, ['user_sync_policy_stale', 'user_sync_conflict', 'user_sync_binding_changed'], true)) {
                throw $error;
            }
            $this->recordProjectionFailure($batch->profiles);
            if (array_any($batch->profiles, fn ($s) => $s->state === 'active')) {
                throw $error;
            }

            return array_map(fn ($s) => $this->outcome($s), $batch->profiles);
        }
    }

    public function apply(UserSnapshot $snapshot): string
    {
        $this->validate($snapshot);
        $this->acceptInactive([$snapshot]);
        $this->refreshAcceptedPolicies([$snapshot]);
        try {
            return (new UserSyncState)->getConnection()->transaction(function () use ($snapshot): string {
                if (! $this->binding($snapshot->policyVersion)) {
                    return 'stale';
                }

                return $this->applyLocked($snapshot);
            });
        } catch (Throwable $error) {
            if ($snapshot->state === 'active') {
                throw $error;
            }
            $this->recordProjectionFailure([$snapshot]);

            return $this->outcome($snapshot);
        }
    }

    /** Commit inactive security facts before any caller-owned native/import transaction. */
    public function acceptInactive(array $snapshots): void
    {
        $inactive = array_values(array_filter($snapshots, fn ($s) => $s->state !== 'active'));
        if ($inactive === []) {
            return;
        }
        $connection = (new UserSyncState)->getConnection();
        Contract::require($connection->transactionLevel() === 0, 'user_sync_outer_transaction_unsupported', 409);
        $connection->transaction(function () use ($inactive): void {
            foreach ($inactive as $snapshot) {
                $this->validate($snapshot);
                if (! $this->binding($snapshot->policyVersion)) {
                    continue;
                }
                // No native lookup belongs in the accepted-security transaction.
                IdentitySession::query()->where('binding_hash', $snapshot->bindingHash)->where('subject', $snapshot->subject)->lockForUpdate()->get();
                [$projection] = $this->projections->synchronize($snapshot->issuer, $snapshot->subject, []);
                [$state, $outcome] = $this->accept($snapshot, $projection);
                if ($outcome === 'pending') {
                    $work = $this->graph->make(UserSyncWorkRepository::class);
                    $request = $work->register($snapshot->subject);
                    if ($request->completed_generation >= $request->generation) {
                        $work->request($snapshot->subject);
                    }
                }
                if ($outcome !== 'stale') {
                    IdentitySession::query()->where('binding_hash', $snapshot->bindingHash)->where('subject', $snapshot->subject)->delete();
                }
            }
        });
    }

    /** For bootstrap only: inactive facts must already have committed outside its transaction. */
    public function applyAssociated(UserSnapshot $snapshot): string
    {
        $this->validate($snapshot);
        if ($snapshot->state !== 'active') {
            $state = UserSyncState::query()->whereKey($this->stateId($snapshot))->first();
            Contract::require($state && $state->version >= $snapshot->version, 'user_sync_acceptance_required', 409);
        }
        if (! $this->binding($snapshot->policyVersion)) {
            return 'stale';
        }

        return $this->applyLocked($snapshot);
    }

    public function nativePending(?string $subject = null): int
    {
        return UserSyncState::query()->where('binding_hash', $this->config->bindingHash())->where('version', '>', 0)->where('native_status', 'pending')->when($subject !== null, fn ($q) => $q->where('subject', $subject))->count();
    }

    /** A fresh proof for already accepted facts survives a failed native-only retry. */
    private function refreshAcceptedPolicies(array $snapshots): void
    {
        foreach ($snapshots as $snapshot) {
            if ($snapshot->state !== 'active') {
                continue;
            }
            $this->validate($snapshot);
            $observed = UserSyncState::query()->whereKey($this->stateId($snapshot))->first();
            if (! $observed || $observed->version !== $snapshot->version || $observed->policy_version >= $snapshot->policyVersion) {
                continue;
            }
            $observed->getConnection()->transaction(function () use ($snapshot): void {
                if (! $this->binding($snapshot->policyVersion)) {
                    return;
                }
                $state = UserSyncState::query()->whereKey($this->stateId($snapshot))->lockForUpdate()->first();
                if (! $state || $state->version !== $snapshot->version) {
                    return;
                }
                Contract::require(hash_equals($state->digest, $snapshot->digest()), 'user_sync_conflict', 409);
                if ($snapshot->policyVersion > $state->policy_version) {
                    $state->update(['policy_version' => $snapshot->policyVersion]);
                }
            });
        }
    }

    private function binding(int $policy, bool $strict = false): ?UserSyncBinding
    {
        $binding = UserSyncBinding::query()->createOrFirst(['id' => $this->config->bindingHash()]);
        $binding = UserSyncBinding::query()->whereKey($binding->id)->lockForUpdate()->firstOrFail();
        if ($policy < $binding->policy_version) {
            if ($strict) {
                throw new IdentityException('user_sync_policy_stale', 409);
            }

            return null;
        }
        if ($policy > $binding->policy_version) {
            $binding->update(['policy_version' => $policy]);
        }

        return $binding;
    }

    private function validate(UserSnapshot $snapshot): void
    {
        Contract::require($snapshot->bindingHash === $this->config->bindingHash() && $snapshot->issuer === $this->config->issuer(), 'user_sync_binding_changed', 409);
    }

    private function stateId(UserSnapshot $snapshot): string
    {
        return hash('sha256', $snapshot->bindingHash."\0".$snapshot->issuer."\0".$snapshot->subject);
    }

    private function accept(UserSnapshot $snapshot, IdentityUser $projection): array
    {
        UserSyncState::query()->createOrFirst(['id' => $this->stateId($snapshot)], ['binding_hash' => $snapshot->bindingHash, 'issuer' => $snapshot->issuer, 'subject' => $snapshot->subject, 'projection_id' => $projection->id]);
        $state = UserSyncState::query()->whereKey($this->stateId($snapshot))->lockForUpdate()->firstOrFail();
        if ($snapshot->version < $state->version) {
            return [$state, 'stale'];
        }
        if ($snapshot->version === $state->version) {
            Contract::require(hash_equals($state->digest, $snapshot->digest()), 'user_sync_conflict', 409);
            if ($snapshot->policyVersion > $state->policy_version) {
                $state->update(['policy_version' => $snapshot->policyVersion]);
            }

            return [$state, $state->native_version === $state->version && $state->native_status === 'applied' ? 'unchanged' : 'pending'];
        }
        $state->update(['version' => $snapshot->version, 'policy_version' => $snapshot->policyVersion, 'state' => $snapshot->state, 'profile' => $snapshot->profile, 'digest' => $snapshot->digest(), 'synchronized_at' => now(), 'native_status' => 'pending', 'native_error' => null]);

        return [$state, 'pending'];
    }

    private function applyLocked(UserSnapshot $snapshot): string
    {
        $this->validate($snapshot);
        // Reject stale input before touching an absent or soft-deleted native row.
        $observed = UserSyncState::query()->whereKey($this->stateId($snapshot))->first();
        if ($observed && $snapshot->version < $observed->version) {
            return 'stale';
        }
        if ($observed && $snapshot->version === $observed->version) {
            Contract::require(hash_equals($observed->digest, $snapshot->digest()), 'user_sync_conflict', 409);
            if ($observed->native_version === $observed->version && $observed->native_status === 'applied') {
                $state = UserSyncState::query()->whereKey($observed->id)->lockForUpdate()->firstOrFail();
                if ($snapshot->policyVersion > $state->policy_version) {
                    $state->update(['policy_version' => $snapshot->policyVersion]);
                }

                return 'unchanged';
            }
        }
        $existing = IdentityUser::query()->where('identity_key', hash('sha256', $snapshot->issuer."\0".$snapshot->subject))->first();
        $user = $existing ? $this->users->linked($existing, true) : null;
        [$projection] = $this->projections->synchronize($snapshot->issuer, $snapshot->subject, []);
        [$state, $outcome] = $this->accept($snapshot, $projection);
        if (in_array($outcome, ['stale', 'unchanged'], true)) {
            return $outcome;
        }
        $this->projections->applyAccepted($projection, $state);
        if (! $user && $this->users->linked($projection, false)) {
            throw new IdentityException('user_sync_association_changed', 503);
        }
        if ($user) {
            if ($this->graph->make(ProjectionOwnership::class)->native($user, $projection)) {
                $this->mapper->synchronize($user, $this->projections->present($projection));
            }
        } elseif ($snapshot->state === 'active' && $this->config->value('sync.provision_missing', false) === true && $this->config->value('users.model') !== null) {
            $this->graph->make(IdentityUserResolver::class)->resolve($projection);
        }
        $state->update(['native_version' => $state->version, 'native_status' => 'applied', 'native_error' => null]);
        $eventUser = $this->projections->present($projection);
        $projection->getConnection()->afterCommit(fn () => ProfileSynchronized::dispatch($eventUser, false));

        return 'applied';
    }

    public function recordProjectionFailure(array $snapshots): void
    {
        foreach ($snapshots as $snapshot) {
            $this->validate($snapshot);
            if ($snapshot->state === 'active') {
                continue;
            }
            UserSyncState::query()->whereKey($this->stateId($snapshot))->where('version', $snapshot->version)->where('digest', $snapshot->digest())->where('native_status', 'pending')->update(['native_error' => 'native_projection_failed']);
        }
    }

    private function outcome(UserSnapshot $snapshot): string
    {
        $state = UserSyncState::query()->whereKey($this->stateId($snapshot))->first();

        return ! $state || $state->version !== $snapshot->version ? 'stale' : ($state->native_status === 'applied' ? 'unchanged' : 'native_pending');
    }
}
