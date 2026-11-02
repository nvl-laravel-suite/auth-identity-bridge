<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use JsonSerializable;
use LogicException;

final readonly class ServiceTargetRegistry implements JsonSerializable
{
    /** @var array<string, ServiceTargetContext> */
    private array $targets;

    /**
     * Cache store names are supplied by the trusted host bootstrap, never a request.
     *
     * @param  array<array-key, mixed>  $definitions
     * @param  list<string>  $cacheStores
     */
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

    /** @return list<string> */
    public function names(): array
    {
        return array_keys($this->targets);
    }

    /** @return array{service_targets: list<string>} */
    public function jsonSerialize(): array
    {
        return ['service_targets' => $this->names()];
    }

    /** @return array{service_targets: list<string>} */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    /** @return never */
    public function __serialize(): array
    {
        throw new LogicException('Service registries cannot be serialized.');
    }

    /** @param array<array-key, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new LogicException('Service registries must be constructed from trusted definitions.');
    }
}
