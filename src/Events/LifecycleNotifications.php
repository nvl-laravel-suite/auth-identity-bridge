<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Events;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Connection;
use Throwable;

/** Best-effort notifications. The committed transition never depends on a listener. */
final readonly class LifecycleNotifications
{
    public function __construct(private Dispatcher $events) {}

    public function afterCommit(Connection $connection, object $event): void
    {
        // Capture this graph's dispatcher and immutable payload now, not ambient app() later.
        $dispatch = function () use ($event): void {
            try {
                $this->events->dispatch($event);
            } catch (Throwable) {
                // No retry of authentication or security transitions for optional notifications.
            }
        };
        if ($connection->transactionLevel() > 0) {
            $connection->afterCommit($dispatch);
        } else {
            $dispatch();
        }
    }
}
