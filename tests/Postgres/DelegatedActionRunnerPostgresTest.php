<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Postgres;

use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Tests\Delegation\DelegationManagerTest;
use Illuminate\Support\Facades\DB;

class DelegatedActionRunnerPostgresTest extends DelegationManagerTest
{
    use UsesIsolatedPostgres;

    public function test_another_worker_cannot_change_the_native_fence_inside_a_delegated_mutation(): void
    {
        $runner = $this->actions();
        $contender = null;
        $row = IdentitySession::query()->findOrFail('ledger-1');
        $result = $this->runAction($runner, mutate: function ($resource) use (&$contender): array {
            $contender = $this->startNativeContender('ledger-1');
            DB::table('owned_documents')->where('id', $resource->id)->update(['title' => 'PostgreSQL committed']);

            return ['title' => 'PostgreSQL committed'];
        });
        $this->assertSame(['title' => 'PostgreSQL committed'], $result);
        $this->finishNativeContender($contender);
        $this->assertSame($row->context_version + 1, $row->fresh()->context_version);
    }
}
