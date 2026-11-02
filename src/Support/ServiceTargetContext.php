<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use Illuminate\Support\Arr;
use JsonSerializable;
use LogicException;

/**
 * A fixed worker authority and destination, independent of interactive consumers.
 *
 * @phpstan-import-type Target from ContextDefinition
 * @phpstan-import-type Http from ContextDefinition
 */
final readonly class ServiceTargetContext implements JsonSerializable
{
    /** @var Target */
    private array $definition;

    /** @param array<array-key, mixed> $definition */
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

    /** @return ($key is 'origin'|'application_id'|'base_url'|'client_id'|'client_secret'|'cache_store' ? non-empty-string : ($key is 'scopes' ? non-empty-list<non-empty-string> : ($key is 'http' ? Http : ($key is 'http.ca_bundle' ? non-empty-string|null : ($key is 'http.max_response_bytes' ? int : mixed))))) */
    public function value(string $key, mixed $default = null): mixed
    {
        return Arr::get($this->definition, $key, $default);
    }

    /** @return non-empty-string */
    public function origin(): string
    {
        return $this->definition['origin'];
    }

    public function issuer(): string
    {
        return $this->origin().'/api/service-auth';
    }

    /** @return non-empty-string */
    public function applicationId(): string
    {
        return $this->definition['application_id'];
    }

    /** @return non-empty-string */
    public function baseUrl(): string
    {
        return $this->definition['base_url'];
    }

    /** @return array{id: non-empty-string, secret: non-empty-string} */
    public function credentials(): array
    {
        return ['id' => $this->definition['client_id'], 'secret' => $this->definition['client_secret']];
    }

    /** @return non-empty-list<non-empty-string> */
    public function scopes(): array
    {
        return $this->definition['scopes'];
    }

    /** @return array{name: string} */
    public function jsonSerialize(): array
    {
        return ['name' => $this->name];
    }

    /** @return array{name: string} */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    /** @return never */
    public function __serialize(): array
    {
        throw new LogicException('Service targets cannot be serialized; persist their trusted name.');
    }

    /** @param array<array-key, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new LogicException('Service targets must be constructed from trusted definitions.');
    }
}
