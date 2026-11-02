<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use Closure;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as HostContainer;

/** Snapshot existing references without resolving new request-dependent services. */
final class ContainerInstances
{
    /** @return array<array-key, mixed> */
    public static function all(HostContainer $container): array
    {
        if (! $container instanceof Container) {
            throw new IdentityException('consumer_dependency_not_supported');
        }

        return (Closure::bind(static fn () => $container->instances, null, Container::class))();
    }
}
