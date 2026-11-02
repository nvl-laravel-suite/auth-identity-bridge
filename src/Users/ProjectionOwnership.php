<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Users;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityProjectionOwner;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Models\IdentityUserLink;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Database\Eloquent\Model;

final class ProjectionOwnership
{
    public function __construct(private IdentityConfig $config, private ConsumerRegistry $registry) {}

    public function common(IdentityUser $projection): bool
    {
        $writer = $this->registry->identityProjectionWriter($this->config->context()->name());
        $this->claim('common', $projection->identity_key, $writer->bindingHash(), $this->config->value('users.identity_projection_epoch', 1), $projection->identity_key, null);

        return $writer->bindingHash() === $this->config->bindingHash();
    }

    public static function physical(Model $user): string
    {
        return hash('sha256', $user->getConnection()->getName()."\0".$user->getTable()."\0".(string) $user->getKey());
    }

    public function native(Model $user, IdentityUser $projection, bool $association = false): bool
    {
        $group = $this->config->value('users.native_group');
        $writer = $group ? $this->registry->get($group['writer'])->bindingHash() : $this->config->bindingHash();
        $physical = self::physical($user);
        // Existing links are immutable; a different model class cannot bypass physical ownership.
        foreach (IdentityUserLink::query()->where('user_id', (string) $user->getKey())->get() as $link) {
            if (! is_subclass_of($link->user_type, Model::class)) {
                continue;
            }
            $other = new $link->user_type;
            if ($other->getConnection()->getName() !== $user->getConnection()->getName() || $other->getTable() !== $user->getTable()) {
                continue;
            }
            Contract::require($link->projection_id === $projection->id, 'identity_native_owner_conflict', 409);
            if ($link->binding_hash !== $this->config->bindingHash()) {
                $otherContext = $this->registry->byBinding($link->binding_hash);
                Contract::require($group !== null && $otherContext->value('users.native_group') === $group, 'identity_native_sharing_denied', 409);
                Contract::require(! $association || IdentityUserLink::query()->where('binding_hash', $this->config->bindingHash())->where('projection_id', $projection->id)->exists(), 'identity_native_explicit_association_required', 409);
            }
        }
        $this->claim('native', $physical, $writer, $group['epoch'] ?? 1, $projection->identity_key, $group['name'] ?? null);

        return $writer === $this->config->bindingHash();
    }

    private function claim(string $kind, string $key, string $writer, int $epoch, string $identity, ?string $group): void
    {
        $id = hash('sha256', $kind."\0".$key);
        IdentityProjectionOwner::query()->createOrFirst(['id' => $id], ['kind' => $kind, 'writer_binding' => $writer, 'epoch' => $epoch, 'identity_key' => $identity, 'group_name' => $group]);
        $owner = IdentityProjectionOwner::query()->whereKey($id)->lockForUpdate()->firstOrFail();
        Contract::require($owner->writer_binding === $writer && $owner->epoch === $epoch && $owner->identity_key === $identity && $owner->group_name === $group, 'identity_projection_owner_fenced', 409);
    }

    /** Explicit refusal until a separately coordinated drain/fence/fresh-fetch procedure exists. */
    public function transfer(string $ownerId, string $expectedBinding, int $expectedEpoch): never
    {
        (new IdentityProjectionOwner)->getConnection()->transaction(function () use ($ownerId, $expectedBinding, $expectedEpoch): void {
            $owner = IdentityProjectionOwner::query()->whereKey($ownerId)->lockForUpdate()->first();
            Contract::require($owner && $owner->writer_binding === $expectedBinding && $owner->epoch === $expectedEpoch, 'identity_projection_owner_fenced', 409);
            throw new IdentityException('identity_projection_handoff_required', 409);
        });
        throw new IdentityException('identity_projection_handoff_required', 409);
    }
}
