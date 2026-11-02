<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Providers;

use IdentityPlatform\Laravel\Console\DoctorIdentityBridge;
use IdentityPlatform\Laravel\IdentityServiceProvider;
use Illuminate\Support\ServiceProvider;

/** Registers the independently installable bridge without enabling unconfigured authentication. */
class AuthIdentityBridgeServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/nvl-auth-identity-bridge.php', 'nvl-auth-identity-bridge');
        if ($this->app['config']->get('nvl-auth-identity-bridge.enabled', false) === true) {
            $this->app->register(IdentityServiceProvider::class);
        }
    }

    public function boot(): void
    {
        $this->commands([DoctorIdentityBridge::class]);
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../resources/config/nvl-auth-identity-bridge.php' => config_path('nvl-auth-identity-bridge.php'),
                __DIR__.'/../../config/identity.php' => config_path('identity.php'),
            ], 'nvl-auth-identity-bridge-config');
            $this->publishesMigrations([
                __DIR__.'/../../database/migrations' => database_path('migrations'),
            ], 'nvl-auth-identity-bridge-migrations');
            $this->publishes([
                __DIR__.'/../../resources/boost/skills' => base_path('.agents/skills'),
            ], 'nvl-auth-identity-bridge-skills');
            $this->publishes([
                __DIR__.'/../../resources/views' => resource_path('views/vendor/identity'),
            ], 'nvl-auth-identity-bridge-views');
        }
    }
}
