<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Callbacks;

use Closure;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityInbox;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserSyncManager;
use Illuminate\Database\Eloquent\Builder;

/** Receipts and local authority changes commit on the consumer's own connection. */
final class CallbackRepository
{
    public function __construct(private ConsumerGraph $graph, private IdentityConfig $config) {}

    public function event(array $event, string $bodyHash): array
    {
        return $this->receive('identity_event', $event['event_id'], $bodyHash, function () use ($event): int {
            if (! in_array($event['type'], [
                'grant.revoked', 'grant.updated', 'entitlements.changed', 'catalog.published',
                'application.configured', 'application.status_changed', 'client.configured',
                'client.revoked', 'client.grants_revoked', 'client.secret_rotated',
                'profile.invalidated',
            ], true)) {
                return 0;
            }
            $query = $this->sessions();
            if (str_starts_with($event['type'], 'grant.') || $event['type'] === 'profile.invalidated') {
                $query->where('subject', $event['subject']);
            }
            $affected = $query->increment('context_version', 1, ['snapshot' => null, 'application_context' => null]);
            if ($this->config->value('sync.enabled', false) === true) {
                if ($event['subject'] === null) {
                    $this->graph->make(UserSyncManager::class)->requestBinding();
                } else {
                    $this->graph->make(UserSyncManager::class)->request($event['subject']);
                }
            }

            return $affected;
        });
    }

    public function logout(array $claims, string $bodyHash): array
    {
        return $this->receive('oidc_logout', $claims['jti'], $bodyHash, function () use ($claims): int {
            $query = $this->sessions();
            if (isset($claims['sid'])) {
                $query->where('sid', $claims['sid']);
            }
            if (isset($claims['sub'])) {
                $query->where('subject', $claims['sub']);
            }

            return $query->delete();
        });
    }

    private function receive(string $protocol, string $messageId, string $bodyHash, Closure $effect): array
    {
        $binding = $this->config->bindingHash();
        $id = hash('sha256', $binding."\0".$protocol."\0".$messageId);

        return (new IdentityInbox)->getConnection()->transaction(function () use ($id, $binding, $protocol, $messageId, $bodyHash, $effect): array {
            // Laravel protects the attempted insert with a savepoint inside this transaction.
            $receipt = IdentityInbox::query()->createOrFirst(['id' => $id], [
                'binding_hash' => $binding, 'protocol' => $protocol, 'message_id' => $messageId,
                'body_hash' => $bodyHash, 'received_at' => now(),
            ]);
            if ($receipt->binding_hash !== $binding || $receipt->protocol !== $protocol ||
                $receipt->message_id !== $messageId || ! hash_equals($receipt->body_hash, $bodyHash)) {
                throw new IdentityException('callback_replay_conflict', 409);
            }

            return $receipt->wasRecentlyCreated
                ? ['duplicate' => false, 'affected' => $effect()]
                : ['duplicate' => true, 'affected' => 0];
        });
    }

    private function sessions(): Builder
    {
        return IdentitySession::query()->where('binding_hash', $this->config->bindingHash());
    }
}
