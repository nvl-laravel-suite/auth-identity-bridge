<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Identity;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;

class RefreshIdentityUser implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable;

    public int $tries = 10;

    public function __construct(public readonly string $requestId) {}

    public function backoff(): array
    {
        return [5, 15, 30, 60, 300, 900, 3600];
    }

    public function handle(Identity $identity): void
    {
        $row = UserSyncRequest::query()->find($this->requestId);
        if ($row === null) {
            return;
        }
        $graph = $identity->byBinding($row->binding_hash);
        $manager = $graph->make(UserSyncManager::class);
        try {
            $manager->process($this->requestId);
        } catch (IdentityException $error) {
            if ($error->status === 429 || $error->status >= 500 || in_array($error->errorCode, ['user_sync_subject_missing', 'user_sync_policy_stale', 'user_sync_page_pending', 'user_sync_busy'], true)) {
                $this->release($error->retryAfter ?? 30);

                return;
            }
            throw $error;
        }
    }
}
