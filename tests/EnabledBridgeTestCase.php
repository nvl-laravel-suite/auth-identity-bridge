<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests;

use IdentityPlatform\Laravel\Providers\AuthIdentityBridgeServiceProvider;

/** Exercises Composer discovery with the ordinary configured package fixtures. */
abstract class EnabledBridgeTestCase extends TestCase
{
    protected function getPackageProviders($app): array
    {
        $app['config']->set('nvl-auth-identity-bridge.enabled', true);

        return [AuthIdentityBridgeServiceProvider::class];
    }
}
