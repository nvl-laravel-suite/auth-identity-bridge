<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use Illuminate\Support\Arr;
use JsonSerializable;
use LogicException;

/** A fixed worker authority and destination, independent of interactive consumers. */
final readonly class ServiceTargetContext implements JsonSerializable
{
    private array $definition;

    public function __construct(private string $name, #[\SensitiveParameter] array $definition)
    {
        $snapshot = ContextDefinition::snapshot($definition);
        ContextDefinition::target($name, $snapshot);
        sort($snapshot['scopes'], SORT_STRING);
        $this->definition = $snapshot;
    }

    public function name(): string
    {
        return $this->name;
    }

    public function value(string $key, mixed $default = null): mixed
    {
        return Arr::get($this->definition, $key, $default);
    }

    public function origin(): string
    {
        return $this->definition['origin'];
    }

    public function issuer(): string
    {
        return $this->origin().'/api/service-auth';
    }

    public function applicationId(): string
    {
        return $this->definition['application_id'];
    }

    public function baseUrl(): string
    {
        return $this->definition['base_url'];
    }

    public function credentials(): array
    {
        return ['id' => $this->definition['client_id'], 'secret' => $this->definition['client_secret']];
    }

    public function scopes(): array
    {
        return $this->definition['scopes'];
    }

    public function jsonSerialize(): array
    {
        return ['name' => $this->name];
    }

    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    public function __serialize(): array
    {
        throw new LogicException('Service targets cannot be serialized; persist their trusted name.');
    }

    public function __unserialize(array $data): void
    {
        throw new LogicException('Service targets must be constructed from trusted definitions.');
    }
}
