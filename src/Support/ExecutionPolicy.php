<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Delegation\DelegationExecutionGuard;
use Illuminate\Contracts\Container\Container;

/** Delegation restrictions inspect only an already selected request, never invent one. */
final readonly class ExecutionPolicy
{
    public function __construct(private Container $app) {}

    public function assertQueueAllowed(mixed $job): void
    {
        $graph = ContainerInstances::all($this->app)[ConsumerGraph::class] ?? null;
        if ($graph !== null) {
            $graph->make(DelegationExecutionGuard::class)->assertQueueAllowed($job);
        }
    }

    public function assertOutboundAllowed(): void
    {
        $graph = ContainerInstances::all($this->app)[ConsumerGraph::class] ?? null;
        if ($graph !== null) {
            $graph->make(DelegationExecutionGuard::class)->assertOutboundAllowed();
        }
    }
}
