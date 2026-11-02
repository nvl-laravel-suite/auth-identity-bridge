<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Models\IdentityUserLink;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserSnapshot;
use IdentityPlatform\Laravel\Sync\UserSyncBinding;
use IdentityPlatform\Laravel\Sync\UserSyncState;
use IdentityPlatform\Laravel\Sync\UserSyncWorkRepository;
use Illuminate\Contracts\Auth\Authenticatable;

/** Associates only an already accepted target proof to a trusted stored same-person link. */
final class NativeUserAssociation
{
    public function __construct(private IdentityConfig $config, private ConsumerRegistry $registry, private ProjectionOwnership $ownership, private UserSyncWorkRepository $work) {}

    public function associate(UserSnapshot $proof, string $sourceBinding, int|string $nativeId): Authenticatable
    {
        Contract::require($proof->bindingHash === $this->config->bindingHash() && $proof->issuer === $this->config->issuer() && $proof->state === 'active', 'identity_native_proof_invalid', 409);
        $group = $this->config->value('users.native_group');
        $source = $this->registry->byBinding($sourceBinding);
        Contract::require($group !== null && $source->value('users.native_group') === $group && $source->issuer() === $proof->issuer && $sourceBinding !== $proof->bindingHash, 'identity_native_sharing_denied', 409);
        $model = $this->config->value('users.model');

        return (new IdentityUserLink)->getConnection()->transaction(function () use ($proof, $sourceBinding, $nativeId, $model): Authenticatable {
            $binding = UserSyncBinding::query()->whereKey($proof->bindingHash)->lockForUpdate()->firstOrFail();
            Contract::require($binding->policy_version === $proof->policyVersion, 'identity_native_proof_invalid', 409);
            $user = $model::query()->whereKey($nativeId)->lockForUpdate()->first();
            Contract::require($user !== null && (string) $user->getKey() === (string) $nativeId, 'identity_native_proof_invalid', 409);
            $projection = IdentityUser::query()->where('identity_key', hash('sha256', $proof->issuer."\0".$proof->subject))->lockForUpdate()->first();
            Contract::require($projection !== null, 'identity_native_proof_invalid', 409);
            $state = UserSyncState::query()->where('binding_hash', $proof->bindingHash)->where('projection_id', $projection->id)->lockForUpdate()->first();
            Contract::require($state && $state->version === $proof->version && $state->policy_version === $proof->policyVersion && $state->state === 'active' && hash_equals($state->digest, $proof->digest()), 'identity_native_proof_invalid', 409);
            $source = IdentityUserLink::query()->where('binding_hash', $sourceBinding)->where('projection_id', $projection->id)->lockForUpdate()->first();
            Contract::require($source && $source->user_id === (string) $nativeId, 'identity_native_proof_invalid', 409);
            $sourceModel = new $source->user_type;
            $sourceUser = $sourceModel->newQuery()->whereKey($nativeId)->first();
            Contract::require($sourceUser !== null && NativeOwner::key($sourceUser) === $source->owner_key, 'identity_native_proof_invalid', 409);
            Contract::require($sourceModel->getTable() === $user->getTable() && $sourceModel->getConnection()->getName() === $user->getConnection()->getName(), 'identity_native_proof_invalid', 409);
            $existing = IdentityUserLink::query()->where('binding_hash', $proof->bindingHash)->where('projection_id', $projection->id)->lockForUpdate()->first();
            Contract::require(! $existing || ($existing->user_id === (string) $nativeId && $existing->owner_key === NativeOwner::key($user)), 'identity_native_owner_conflict', 409);
            $this->ownership->native($user, $projection);
            if (! $existing) {
                IdentityUserLink::query()->create(['id' => hash('sha256', $proof->bindingHash."\0".$projection->id), 'binding_hash' => $proof->bindingHash, 'projection_id' => $projection->id, 'user_type' => $model, 'user_id' => (string) $nativeId, 'owner_key' => NativeOwner::key($user)]);
            }
            $state->update(['native_status' => 'pending', 'native_error' => null]);
            $this->work->request($proof->subject);

            return $user;
        });
    }
}
