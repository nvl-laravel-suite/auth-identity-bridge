<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Sync\RefreshIdentityUser;
use Illuminate\Http\Request;

/** Synchronous delegation does not propagate browser authority into jobs or machine callers. */
class DelegationExecutionGuard
{
    public function __construct(private ConsumerGraph $graph, private OverlayRepository $overlays) {}

    public function assertQueueAllowed(mixed $job): void
    {
        $name = is_string($job) ? $job : (is_object($job) ? $job::class : null);
        if (! in_array($name, [ReportDelegatedAction::class, RefreshIdentityUser::class], true) && $this->activeBrowser()) {
            throw new IdentityException('delegation_queue_forbidden', 403);
        }
    }

    public function assertOutboundAllowed(): void
    {
        if ($this->activeBrowser()) {
            throw new IdentityException('delegation_outbound_forbidden', 403);
        }
    }

    private function activeBrowser(): bool
    {
        $request = $this->graph->make(Request::class);
        $id = $request->hasSession() ? $request->session()->get('identity.session') : null;

        return is_string($id) && $this->overlays->find($id) !== null;
    }
}
