<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Contracts\Container\Container;

/** Resolve only the currently selected graph; never select a default consumer for a job. */
final class CurrentDecisionPresenter
{
    public function __construct(private Container $container) {}

    public function current(): CurrentDecisionView
    {
        try {
            return $this->container->make(IdentityAccess::class)->currentDecisionView();
        } catch (IdentityException) {
            return new CurrentDecisionView;
        }
    }
}
