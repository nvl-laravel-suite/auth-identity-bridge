<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use Illuminate\Cache\Repository;
use Illuminate\Session\CacheBasedSessionHandler;
use Illuminate\Session\SessionManager;

/** Each request gets fresh framework stores; shared backend keys are consumer bound. */
final class ConsumerSessionManager extends SessionManager
{
    public function __construct($container, private ConsumerContext $context, private bool $preserveDefaultNamespace)
    {
        parent::__construct($container);
    }

    protected function buildSession($handler)
    {
        $bound = new BoundSessionHandler($handler, $this->context->bindingHash(), $this->preserveDefaultNamespace, new SessionGarbageCollector($this->container, $this->context, $this->preserveDefaultNamespace));
        $bound->setRequest($this->container->make('request'));

        return parent::buildSession($bound);
    }

    protected function createCacheHandler($driver)
    {
        $name = $this->config->get('session.store') ?: $driver;
        $repository = $this->container->make('cache')->store($name);
        $isolated = new Repository(clone $repository->getStore());

        return new CacheBasedSessionHandler($isolated, $this->config->get('session.lifetime'));
    }
}
