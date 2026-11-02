<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Middleware;

use Closure;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\ConsumerRouteCollection;
use IdentityPlatform\Laravel\Support\ContainerInstances;
use IdentityPlatform\Laravel\Support\ContextDefinition;
use IdentityPlatform\Laravel\Support\FrameworkSessionScope;
use Illuminate\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Symfony\Component\HttpFoundation\Response;

/** Global middleware: trusted selection happens before Router gathers controller middleware. */
final readonly class SelectConsumer
{
    public function __construct(private Container $app, private ConsumerRegistry $registry, private Identity $identity, private Router $router, private FrameworkSessionScope $sessions) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): mixed
    {
        if ($this->registry->names() === []) {
            return $next($request);
        }
        if (! $this->router->getRoutes() instanceof ConsumerRouteCollection && ConsumerRouteCollection::needsAuthorityMatching($this->registry)) {
            $this->router->setRoutes(new ConsumerRouteCollection($this->router->getRoutes(), $this->registry));
        }
        $route = $this->router->getRoutes()->match($request);
        $route->flushController();
        $name = $route->defaults['identity_consumer'] ?? null;
        try {
            if ($name !== null) {
                ContextDefinition::require(is_string($name), 'unknown_consumer_route');
                $context = $this->registry->get($name);
                ContextDefinition::require(ContextDefinition::originKey($request->getSchemeAndHttpHost()) === ContextDefinition::originKey($context->appOrigin()), 'unknown_consumer_route');
                if ($context->hasBrowser()) {
                    $prefix = $context->value('routes.path_prefix');
                    ContextDefinition::require(is_string($prefix), 'unknown_consumer_route');
                    ContextDefinition::require(ContextDefinition::withinPath(ConsumerRegistry::requestPath($request->getPathInfo()), $prefix), 'unknown_consumer_route');
                    if ($context->value('routes.enabled')) {
                        ContextDefinition::require($this->registry->forOriginAndPath($request->getSchemeAndHttpHost(), $request->getPathInfo()) === $context, 'consumer_route_mismatch');
                    }
                }
            } else {
                $context = $this->registry->forOriginAndPath($request->getSchemeAndHttpHost(), $request->getPathInfo());
            }
        } catch (IdentityException) {
            throw new IdentityException('unknown_consumer_route', 404);
        }
        $graph = $this->identity->consumer($context->name(), $request);
        $previous = ContainerInstances::all($this->app)[ConsumerGraph::class] ?? null;
        $this->app->instance(ConsumerGraph::class, $graph);
        $request->attributes->set('identity.consumer', $context->name());
        try {
            if (! $context->hasBrowser() || ($route->defaults['identity_stateless'] ?? false)) {
                if (in_array('web', $route->middleware(), true)) {
                    throw new IdentityException('consumer_route_mismatch', 500);
                }

                return $this->sessions->run($graph, $request, $next, false);
            }
            $cookie = preg_quote($context->sessionSettings()['cookie'], '/');
            $cookieHeader = $request->server('HTTP_COOKIE', '');
            if (! is_string($cookieHeader) || preg_match_all('/(?:^|;\s*)'.$cookie.'=/', $cookieHeader) > 1) {
                throw new IdentityException('duplicate_session_cookie', 400);
            }

            return $this->sessions->run($graph, $request, $next);
        } finally {
            $route->flushController();
            $this->app->forgetInstance(ConsumerGraph::class);
            if ($previous !== null) {
                $this->app->instance(ConsumerGraph::class, $previous);
            }
            $request->attributes->remove('identity.consumer');
        }
    }
}
