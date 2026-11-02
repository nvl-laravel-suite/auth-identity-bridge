<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use IdentityPlatform\Laravel\Support\ConsumerContext;

final class LocalDestinationResolver implements PostContextDestinationResolver
{
    public function resolve(ConsumerContext $consumer, string $returnPath): BrowserDestination
    {
        return BrowserDestination::local($returnPath);
    }
}
