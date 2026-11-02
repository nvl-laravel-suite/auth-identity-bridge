<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

/** Explicit host opt-in; registrations live in host provider code, never cached closures. */
final class IdentityAuthorizationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singletonIf(AbilityRegistry::class);
        $this->app->extend(GateContract::class, fn (GateContract $gate, $app) => new IdentityGate(
            $app, $gate, $app->make(AbilityRegistry::class), fn () => ($app['auth']->userResolver())()
        ));
        Gate::clearResolvedInstance(GateContract::class);
    }
}
