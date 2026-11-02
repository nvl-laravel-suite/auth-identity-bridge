<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use JsonSerializable;
use LogicException;

final readonly class ServiceTargetRegistry implements JsonSerializable
{
    private array $targets;

    /** Cache store names are supplied by the trusted host bootstrap, never a request. */
    public function __construct(#[\SensitiveParameter] array $definitions, array $cacheStores)
    {
        $targets = [];
        foreach (ContextDefinition::snapshot($definitions) as $name => $definition) {
            ContextDefinition::name($name);
            ContextDefinition::require(is_array($definition));
            $target = new ServiceTargetContext($name, $definition);
            ContextDefinition::require(in_array($target->value('cache_store'), $cacheStores, true));
            $targets[$name] = $target;
        }
        $this->targets = $targets;
    }

    public function get(string $name): ServiceTargetContext
    {
        return $this->targets[$name] ?? throw new IdentityException('unknown_service_target');
    }

    public function names(): array
    {
        return array_keys($this->targets);
    }

    public function jsonSerialize(): array
    {
        return ['service_targets' => $this->names()];
    }

    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    public function __serialize(): array
    {
        throw new LogicException('Service registries cannot be serialized.');
    }

    public function __unserialize(array $data): void
    {
        throw new LogicException('Service registries must be constructed from trusted definitions.');
    }
}
