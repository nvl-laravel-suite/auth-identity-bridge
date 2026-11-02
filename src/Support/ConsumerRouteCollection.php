<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Http\Request;
use Illuminate\Routing\RouteCollection;
use Illuminate\Routing\RouteCollectionInterface;

/** Laravel host matching omits ports; trusted authority selects package routes first. */
final class ConsumerRouteCollection extends RouteCollection
{
    public function __construct(RouteCollectionInterface $routes, private ConsumerRegistry $registry)
    {
        foreach ($routes->getRoutes() as $route) {
            $this->add($route);
        }
    }

    public static function hostParameter(string $name): string
    {
        return 'identity_host_'.substr(hash('sha256', $name), 0, 12);
    }

    public static function needsAuthorityMatching(ConsumerRegistry $registry): bool
    {
        $seen = [];
        foreach ($registry->names() as $name) {
            $context = $registry->get($name);
            if (! $context->hasBrowser() || ! $context->value('routes.enabled')) {
                continue;
            }
            $host = strtolower(ContextDefinition::origin($context->appOrigin())['host']);
            $prefix = $context->value('routes.path_prefix');
            ContextDefinition::require($prefix !== null, 'unknown_consumer_route');
            foreach ($seen[$host] ?? [] as $otherPrefix) {
                if (ContextDefinition::withinPath($prefix, $otherPrefix) || ContextDefinition::withinPath($otherPrefix, $prefix)) {
                    return true;
                }
            }
            $seen[$host][] = $prefix;
        }

        return false;
    }

    public function match(Request $request)
    {
        try {
            $context = $this->registry->forOriginAndPath($request->getSchemeAndHttpHost(), $request->getPathInfo());
        } catch (IdentityException) {
            return parent::match($request);
        }
        foreach ($this->getRoutesByName() as $route) {
            if (($route->defaults['identity_consumer'] ?? null) === $context->name() && $route->matches($request)) {
                return $route->bind($request);
            }
        }

        return parent::match($request);
    }
}
