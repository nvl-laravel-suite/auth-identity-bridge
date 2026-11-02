<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;

/** Compatibility-facing API backed exclusively by one immutable consumer definition. */
final readonly class IdentityConfig
{
    public function __construct(private ConsumerContext $context) {}

    public function context(): ConsumerContext
    {
        return $this->context;
    }

    public function value(string $key, mixed $default = null): mixed
    {
        return $key === 'connection' ? $this->context->connection() : $this->context->value($key, $default);
    }

    public function origin(): string
    {
        return $this->context->origin();
    }

    public function appOrigin(): string
    {
        return $this->context->appOrigin();
    }

    public function issuer(): string
    {
        return $this->context->issuer();
    }

    public function serviceIssuer(): string
    {
        return $this->context->serviceIssuer();
    }

    public function applicationId(): string
    {
        return $this->context->applicationId();
    }

    public function clientId(): string
    {
        return $this->context->clientId();
    }

    public function credentials(string $plane): array
    {
        return $this->context->credentials($plane);
    }

    public function bindingHash(): string
    {
        return $this->context->bindingHash();
    }

    public function routeName(string $action): string
    {
        return $this->context->routeName($action);
    }

    public function url(string $action): string
    {
        $path = match ($action) {
            'callback' => $this->value('browser.redirect_uri'),
            'signed-out' => $this->value('browser.post_logout_redirect_uri'),
            'events' => $this->value('routes.event_uri'),
            'backchannel-logout' => $this->value('routes.backchannel_logout_uri'),
            default => null,
        };
        if ($path !== null) {
            return $path;
        }
        $suffix = match ($action) {
            'application-contexts' => '/auth/application-contexts', 'application-context.current', 'application-context.select' => '/auth/application-context', 'application-context.clear' => '/auth/application-context/clear',
            'entry' => '/auth/entry', 'login' => '/auth/sign-in', 'contexts' => '/auth/contexts', 'context.select' => '/auth/context',
            'logout' => '/auth/sign-out', 'central-logout' => '/auth/central-sign-out',
            'delegation.start' => '/auth/delegation/start', 'delegation.callback' => '/auth/delegation/callback', 'delegation.stop' => '/auth/delegation/stop',
            default => throw new IdentityException('unknown_consumer_route'),
        };

        return $this->appOrigin().rtrim($this->value('routes.path_prefix'), '/').$suffix;
    }
}
