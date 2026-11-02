<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Postgres;

use IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Tests\Authorization\OrdinaryActionRunnerTest;

class OrdinaryActionRunnerPostgresTest extends OrdinaryActionRunnerTest
{
    use UsesIsolatedPostgres;

    public function test_another_worker_cannot_change_the_native_fence_inside_an_ordinary_mutation(): void
    {
        $contender = null;
        $request = app('request');
        $row = IdentitySession::query()->findOrFail('ordinary-ledger');
        $result = app(OrdinaryActionRunner::class)->run($request, fn () => null, function () use (&$contender): array {
            $contender = $this->startNativeContender('ordinary-ledger');

            return ['committed' => true];
        });
        $this->assertSame(['committed' => true], $result);
        $this->finishNativeContender($contender);
        $this->assertSame($row->context_version + 1, $row->fresh()->context_version);
    }
}
