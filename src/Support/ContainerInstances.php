<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use Closure;
use Illuminate\Container\Container;

/** Snapshot existing references without resolving new request-dependent services. */
final class ContainerInstances
{
    public static function all(Container $container): array
    {
        return (Closure::bind(static fn () => $container->instances, null, Container::class))();
    }
}
