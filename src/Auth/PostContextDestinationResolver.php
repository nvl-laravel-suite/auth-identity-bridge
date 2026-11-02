<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use IdentityPlatform\Laravel\Support\ConsumerContext;

interface PostContextDestinationResolver
{
    /** Bound return path belongs to this source consumer. Never accept a request URL/consumer. */
    public function resolve(ConsumerContext $consumer, string $returnPath): BrowserDestination;
}
