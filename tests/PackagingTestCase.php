<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests;

use IdentityPlatform\Laravel\Providers\AuthIdentityBridgeServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

/** Boots only the Composer-discovered provider with no Identity credentials. */
abstract class PackagingTestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [AuthIdentityBridgeServiceProvider::class];
    }
}
