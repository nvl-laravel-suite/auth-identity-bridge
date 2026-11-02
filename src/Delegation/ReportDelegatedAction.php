<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\Support\IdentityVault;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;

/** A queue payload carries only its outbox row reference, never browser authority. */
class ReportDelegatedAction implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable;

    public int $tries = 10;

    public function __construct(public readonly string $actionId) {}

    /**
     * @return list<positive-int>
     */
    public function backoff(): array
    {
        return [5, 15, 30, 60, 300, 900, 3600];
    }

    public function handle(Identity $identity): void
    {
        $row = IdentityDelegatedAction::query()->find($this->actionId);
        if ($row === null) {
            return;
        }
        $graph = $identity->byBinding($row->binding_hash);
        $actions = $graph->make(DelegatedActionRepository::class);
        $vault = $graph->make(IdentityVault::class);
        $client = $graph->make(ConsumerClient::class);
        $action = $actions->find($this->actionId);
        if (! $action || $action->reported_at !== null) {
            return;
        }
        $receipt = $vault->open($action->receipt_vault, 'delegated-action:'.$action->id);
        $client->report($receipt, $action->outcome, $action->outcome === 'rejected' ? 'local.rejected' : null);
        $actions->reported($action->id);
    }
}
