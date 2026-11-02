<?php

declare(strict_types=1);

use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\IdentityServiceProvider;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Tests\EnabledBridgeTestCase;

uses(EnabledBridgeTestCase::class);

it('activates the original bound consumer only after explicit bridge opt-in', function (): void {
    expect($this->app->getLoadedProviders()[IdentityServiceProvider::class] ?? false)->toBeTrue()
        ->and(app(ConsumerRegistry::class)->names())->toContain('one')
        ->and(app(Identity::class)->consumer('one')->context->name())->toBe('one');
});
