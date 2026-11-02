<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use Closure;
use IdentityPlatform\Laravel\Auth\IdentityRequestGuard;
use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Cookie\CookieJar;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Facade;
use ReflectionProperty;

/** Sequential-worker adapter. Does not claim concurrent coroutine isolation. */
final readonly class FrameworkSessionScope
{
    public function __construct(private Container $app, private ConsumerRegistry $registry) {}

    public function run(ConsumerGraph $graph, Request $request, Closure $next, bool $browser = true): mixed
    {
        $previous = (Closure::bind(static fn () => Facade::$resolvedInstance[IdentityAccess::class] ?? null, null, Facade::class))();
        Facade::clearResolvedInstance(IdentityAccess::class);
        try {
            return $browser ? $this->runBrowser($graph, $request, $next) : $next($request);
        } finally {
            Facade::clearResolvedInstance(IdentityAccess::class);
            if ($previous !== null) {
                (Closure::bind(static function () use ($previous): void {
                    Facade::$resolvedInstance[IdentityAccess::class] = $previous;
                }, null, Facade::class))();
            }
        }
    }

    private function runBrowser(ConsumerGraph $graph, Request $request, Closure $next): mixed
    {
        ContextDefinition::require($this->app instanceof Application, 'consumer_dependency_not_supported');
        // Both framework redirect entry points retain the session store they first resolve.
        $keys = ['session', 'session.store', 'auth', 'auth.driver', 'cookie', StartSession::class, 'redirect', ResponseFactory::class];
        $instances = array_intersect_key(ContainerInstances::all($this->app), array_flip($keys));
        $facadeState = new ReflectionProperty(Facade::class, 'resolvedInstance');
        $resolvedFacades = $facadeState->getValue();
        ContextDefinition::require($resolvedFacades === null || is_array($resolvedFacades), 'consumer_dependency_not_supported');
        $facades = array_intersect_key($resolvedFacades ?? [], array_flip(['session', 'auth', 'cookie', 'redirect', ResponseFactory::class]));
        $config = $this->app->make('config');
        $sessionConfig = $config->get('session');
        $authConfig = $config->get('auth');
        $userResolver = $request->getUserResolver();
        $session = (Closure::bind(static fn () => $request->session, null, \Symfony\Component\HttpFoundation\Request::class))();
        try {
            $settings = $graph->context->sessionSettings();
            $config->set('session', $settings);
            foreach ($keys as $key) {
                $this->app->forgetInstance($key);
            }
            foreach (['session', 'auth', 'cookie', 'redirect', ResponseFactory::class] as $key) {
                Facade::clearResolvedInstance($key);
            }
            $this->app->instance('cookie', (new CookieJar)->setDefaultPathAndDomain($settings['path'], $settings['domain'], $settings['secure'], $settings['same_site']));
            $this->app->instance('session', new ConsumerSessionManager($this->app, $graph->context, $graph->context->name() === $this->registry->defaultName()));
            $guardName = $graph->context->value('routes.guard');
            $config->set('auth.defaults.guard', $guardName);
            $config->set('auth.guards.'.$guardName, ['driver' => 'identity']);
            $auth = new AuthManager($this->app);
            $auth->extend('identity', fn () => new IdentityRequestGuard(static function () use ($graph) {
                try {
                    return $graph->make(IdentityAccess::class)->user();
                } catch (IdentityException $error) {
                    if ($error->errorCode === 'delegation_check_required') {
                        return null;
                    }
                    throw $error;
                }
            }, $request));
            $this->app->instance('auth', $auth);
            $request->setUserResolver(static fn (string|\UnitEnum|null $guard = null) => $auth->guard($guard)->user());

            return $next($request);
        } finally {
            $config->set('session', $sessionConfig);
            $config->set('auth', $authConfig);
            foreach ($keys as $key) {
                $this->app->forgetInstance($key);
                if (array_key_exists($key, $instances)) {
                    $this->app->instance($key, $instances[$key]);
                }
            }
            $currentFacades = $facadeState->getValue();
            ContextDefinition::require($currentFacades === null || is_array($currentFacades), 'consumer_dependency_not_supported');
            (Closure::bind(static function () use ($facades, $currentFacades): void {
                foreach (['session', 'auth', 'cookie', 'redirect', ResponseFactory::class] as $key) {
                    unset($currentFacades[$key]);
                }
                Facade::$resolvedInstance = array_replace($currentFacades ?? [], $facades);
            }, null, Facade::class))();
            $request->setUserResolver($userResolver);
            (Closure::bind(static function () use ($request, $session): void {
                $request->session = $session;
            }, null, \Symfony\Component\HttpFoundation\Request::class))();
        }
    }
}
