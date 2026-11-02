<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Http\Middleware;

use Closure;
use IdentityPlatform\Laravel\Delegation\DelegationManager;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** Installed on web before host authentication/policies; every unregistered route fails closed. */
class DelegationBoundary
{
    private const EXIT_ROUTES = ['delegation.stop', 'delegation.callback', 'logout', 'central-logout'];

    public function __construct(private DelegationManager $delegations, private IdentityConfig $config) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): mixed
    {
        $overlay = $this->delegations->current($request);
        if (! $overlay) {
            return $next($request);
        }
        $route = $request->route()?->getName();
        if (in_array($route, array_map(fn ($action) => $this->config->routeName($action), self::EXIT_ROUTES), true)) {
            return $next($request);
        }
        $operation = $this->config->value('delegation.routes', [])[$route ?? ''] ?? null;
        if (! is_string($operation) || $overlay->status !== 'active') {
            throw new IdentityException('delegation_route_forbidden', 403);
        }
        $registration = $this->delegations->registration($operation);
        if (! in_array($request->method(), ['GET', 'HEAD'], true) && ! $registration['write']) {
            throw new IdentityException('delegation_operation_forbidden', 403);
        }
        $this->delegations->check($request, $operation);

        return $next($request);
    }
}
