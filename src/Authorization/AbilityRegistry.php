<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

use InvalidArgumentException;
use ReflectionMethod;

/** Trusted host code owns whole prefixes, including names not yet mapped.
 * @api
 *
 * @phpstan-type Mapping array{permission: string, policy: class-string, method: string}
 */
final class AbilityRegistry
{
    /** @var array<string, true> */
    private array $families = [];

    /** @var array<string, Mapping> */
    private array $mappings = [];

    public function family(string $prefix): self
    {
        if (preg_match('/^[a-z][a-z0-9._:-]*[.:]$/D', $prefix) !== 1) {
            throw new InvalidArgumentException('Ability families require an explicit namespace delimiter.');
        }
        $this->families[$prefix] = true;

        return $this;
    }

    /** @param class-string $policy */
    public function map(string $ability, string $permission, string $policy, string $method): self
    {
        if (! $this->owns($ability) || ! Contract::strings([$ability], true) || ! Contract::strings([$permission], true)
            || ! method_exists($policy, $method) || str_starts_with($method, '__') || $method === 'before') {
            throw new InvalidArgumentException('A named ability requires an owned family, central key and public resource policy method.');
        }
        $reflection = new ReflectionMethod($policy, $method);
        if (! $reflection->isPublic() || $reflection->isStatic() || isset($this->mappings[$ability])) {
            throw new InvalidArgumentException('Ability mappings must be unique public instance policy methods.');
        }
        $this->mappings[$ability] = ['permission' => $permission, 'policy' => $policy, 'method' => $method];

        return $this;
    }

    public function owns(string $ability): bool
    {
        return array_any(array_keys($this->families), fn (string $prefix): bool => str_starts_with($ability, $prefix));
    }

    /** @return Mapping|null */
    public function mapping(string $ability): ?array
    {
        return $this->mappings[$ability] ?? null;
    }
}
