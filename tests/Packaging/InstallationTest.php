<?php

declare(strict_types=1);

use IdentityPlatform\Laravel\IdentityServiceProvider;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Tests\PackagingTestCase;

uses(PackagingTestCase::class);

it('boots an unconfigured host without registering Identity browser middleware', function (): void {
    expect($this->app->getLoadedProviders()[IdentityServiceProvider::class] ?? false)->toBeFalse()
        ->and($this->app->bound(ConsumerRegistry::class))->toBeFalse();
    $this->app['router']->get('/bridge-installation', fn () => 'host is available');
    $this->get('/bridge-installation')->assertOk()->assertSee('host is available');
});

it('provides safe diagnostics while the bridge is disabled', function (): void {
    $this->artisan('nvl:auth-identity-bridge:doctor', ['--format' => 'json', '--strict' => true])
        ->expectsOutput('{"enabled":false,"valid":true,"code":"disabled"}')
        ->assertSuccessful();
});
