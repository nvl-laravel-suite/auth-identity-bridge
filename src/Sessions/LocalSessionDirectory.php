<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sessions;

use IdentityPlatform\Laravel\Events\LifecycleNotifications;
use IdentityPlatform\Laravel\Events\LocalSessionEnded;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Models\IdentityUserLink;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Users\NativeOwner;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;

/** Local browser ledgers only; this does not enumerate central Identity sessions. */
class LocalSessionDirectory
{
    public function __construct(private ConsumerGraph $graph, private IdentityConfig $config, private SessionRepository $sessions, private LifecycleNotifications $notifications) {}

    /** @return list<array{id: string, started_at: string, last_activity_at: string, expires_at: string, current: bool}> */
    public function forOwner(Authenticatable $owner): array
    {
        $request = $this->graph->make(Request::class);
        $current = $request->hasSession() ? $request->session()->get('identity.session') : null;

        return $this->owned($owner)->where('expires_at', '>', now())->where('started_at', '>', now()->subSeconds((int) $this->config->value('local.absolute_seconds', 43200)))->where('last_activity_at', '>', now()->subSeconds((int) $this->config->value('local.idle_seconds', 1800)))->orderByDesc('last_activity_at')->get()->map(fn ($row) => [
            'id' => $row->id, 'started_at' => $row->started_at->toIso8601String(), 'last_activity_at' => $row->last_activity_at->toIso8601String(),
            'expires_at' => $row->expires_at->toIso8601String(), 'current' => $row->id === $current,
        ])->all();
    }

    public function revoke(Authenticatable $owner, string $sessionId): bool
    {
        return (new IdentitySession)->getConnection()->transaction(function () use ($owner, $sessionId): bool {
            $row = $this->lock($owner, $sessionId);
            if (! $row || ! $this->sessions->delete($row->id)) {
                return false;
            }
            $this->notifications->afterCommit($row->getConnection(), new LocalSessionEnded($this->config->context()->name(), $row->subject, $row->context_version));

            return true;
        });
    }

    public function lock(Authenticatable $owner, string $sessionId): ?IdentitySession
    {
        return $this->owned($owner)->whereKey($sessionId)->lockForUpdate()->first();
    }

    private function owned(Authenticatable $owner): Builder
    {
        $key = NativeOwner::key($owner);
        $projectionIds = $owner instanceof IdentityUser && $this->config->value('users.model') === null
            ? [$owner->getKey()]
            : IdentityUserLink::query()->where('binding_hash', $this->config->bindingHash())->where('owner_key', $key)->pluck('projection_id')->all();

        return $this->sessions->query()->whereIn('user_id', $projectionIds);
    }
}
