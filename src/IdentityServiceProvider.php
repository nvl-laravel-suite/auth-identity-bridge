<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel;

use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextRegistry;
use IdentityPlatform\Laravel\Auth\IdentityRequestGuard;
use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Console\ImportIdentityUsers;
use IdentityPlatform\Laravel\Console\ReconcileIdentityUsers;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Http\Middleware\ApiCredential;
use IdentityPlatform\Laravel\Http\Middleware\BrowserSafety;
use IdentityPlatform\Laravel\Http\Middleware\DelegationBoundary;
use IdentityPlatform\Laravel\Http\Middleware\Organization;
use IdentityPlatform\Laravel\Http\Middleware\Permission;
use IdentityPlatform\Laravel\Http\Middleware\RecentMfa;
use IdentityPlatform\Laravel\Http\Middleware\RequireSession;
use IdentityPlatform\Laravel\Http\Middleware\Role;
use IdentityPlatform\Laravel\Http\Middleware\SelectConsumer;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\ConsumerRouteCollection;
use IdentityPlatform\Laravel\Support\ContextDefinition;
use IdentityPlatform\Laravel\Support\ExecutionPolicy;
use IdentityPlatform\Laravel\Support\ServiceTargetRegistry;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Kernel as LaravelKernel;
use Illuminate\Http\Request;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Events\JobQueueing;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

class IdentityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/identity.php', 'identity');
        $this->app->singleton(ConsumerRegistry::class, function (Application $app) {
            $config = $app->make(ConfigRepository::class);
            $stores = $config->get('cache.stores', []);
            $connections = $config->get('database.connections', []);
            $configuration = $config->get('identity');
            $defaultConnection = $config->get('database.default');
            ContextDefinition::require(is_array($stores) && is_array($connections) && is_array($configuration) && is_string($defaultConnection));
            $shared = $cacheStores = $connectionNames = [];
            foreach ($stores as $name => $store) {
                ContextDefinition::require(is_string($name) && is_array($store));
                $cacheStores[] = $name;
                if (in_array($store['driver'] ?? null, ['database', 'redis', 'memcached', 'dynamodb', 'file'], true)) {
                    $shared[] = $name;
                }
            }
            foreach (array_keys($connections) as $name) {
                ContextDefinition::require(is_string($name));
                $connectionNames[] = $name;
            }

            return new ConsumerRegistry($configuration, $defaultConnection, $connectionNames, $shared, $cacheStores);
        });
        $this->app->singleton(Identity::class);
        $this->app->singleton(ApplicationContextRegistry::class);
        $this->app->singleton(ServiceTargetRegistry::class, fn (Application $app) => $app->make(ConsumerRegistry::class)->serviceTargets());
        $this->app->bind(ConsumerGraph::class, fn () => throw new IdentityException('consumer_selection_required'));
        foreach (ConsumerGraph::SERVICES as $service) {
            $this->app->bind($service, fn (Application $app) => $app->make(ConsumerGraph::class)->make($service));
        }
        $this->callAfterResolving('url', function (UrlGenerator $url): void {
            if ($this->setupCommand()) {
                return;
            }
            $registry = $this->app->make(ConsumerRegistry::class);
            foreach ($registry->names() as $name) {
                $context = $registry->get($name);
                if ($context->hasBrowser() && $context->value('routes.enabled')) {
                    $url->defaults([ConsumerRouteCollection::hostParameter($name) => parse_url($context->appOrigin(), PHP_URL_HOST)]);
                }
            }
        });
        $this->callAfterResolving(Kernel::class, function (LaravelKernel $kernel): void {
            $kernel->prependMiddleware(SelectConsumer::class);
            $kernel->appendMiddlewareToGroup('web', DelegationBoundary::class);
            $kernel->addToMiddlewarePriorityAfter(StartSession::class, DelegationBoundary::class);
        });
        $this->callAfterResolving(ExceptionHandler::class, function (ExceptionHandler $handler): void {
            // Laravel's routing pipeline renders inner exceptions before outer middleware.
            $handler->renderable(function (IdentityException $error) {
                $response = response()->json(['error' => $error->errorCode], $error->status)
                    ->header('Cache-Control', 'no-store')
                    ->header('Referrer-Policy', 'strict-origin')
                    ->header('X-Content-Type-Options', 'nosniff');
                if ($error->retryAfter !== null) {
                    $response->headers->set('Retry-After', (string) $error->retryAfter);
                }

                return $response;
            });
        });
    }

    public function boot(): void
    {
        $this->commands([ReconcileIdentityUsers::class, ImportIdentityUsers::class]);
        Event::listen(JobQueueing::class, fn (JobQueueing $event) => app(ExecutionPolicy::class)->assertQueueAllowed($event->job));
        Event::listen(JobProcessing::class, fn (JobProcessing $event) => app(ExecutionPolicy::class)->assertQueueAllowed($event->job->resolveName()));
        if (config('nvl-auth-identity-bridge.migrations.enabled', true)) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'identity');
        $router = $this->app->make(Router::class);
        foreach (['safety' => BrowserSafety::class, 'session' => RequireSession::class, 'permission' => Permission::class, 'role' => Role::class, 'organization' => Organization::class, 'mfa' => RecentMfa::class, 'credential' => ApiCredential::class] as $name => $class) {
            $router->aliasMiddleware('identity.'.$name, $class);
        }
        Auth::extend('identity', function (Application $app) {
            $guard = new IdentityRequestGuard(function ($request) {
                try {
                    return app(IdentityAccess::class)->user();
                } catch (IdentityException $error) {
                    if ($error->errorCode === 'delegation_check_required') {
                        return null;
                    }
                    throw $error;
                }
            }, $app->make(Request::class));
            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
        if (! $this->setupCommand()) {
            $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        }
        $this->publishes([__DIR__.'/../config/identity.php' => config_path('identity.php')], 'identity-config');
    }

    private function setupCommand(): bool
    {
        return $this->app->runningConsoleCommand('package:discover', 'vendor:publish');
    }
}
