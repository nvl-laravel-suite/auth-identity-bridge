<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Services;

use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Support\ServiceTargetRegistry;

/** @api */
final readonly class ServiceTokenManager
{
    public function __construct(private ServiceTargetRegistry $targets) {}

    public function target(string $name): ServiceTokenClient
    {
        $context = $this->targets->get($name);

        return new ServiceTokenClient($context, new IdentityHttp($context));
    }
}
