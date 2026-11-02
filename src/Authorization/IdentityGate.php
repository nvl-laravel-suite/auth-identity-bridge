<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

use BackedEnum;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Auth\Access\Gate;
use Illuminate\Auth\Access\Response;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Arr;
use InvalidArgumentException;
use UnitEnum;

/** Inherit framework check/inspect/authorize; keep the host Gate for local abilities. */
final class IdentityGate extends Gate
{
    /** @param callable(): mixed $userResolver */
    public function __construct(Container $container, private GateContract $inner, private AbilityRegistry $registry, callable $userResolver)
    {
        parent::__construct($container, $userResolver);
    }

    /**
     * @param  UnitEnum|string  $ability
     * @param  mixed  $arguments
     */
    public function raw($ability, $arguments = []): mixed
    {
        $ability = $this->abilityName($ability);
        if (! $this->registry->owns($ability)) {
            return $this->inner->raw($ability, $arguments);
        }
        $mapping = $this->registry->mapping($ability);
        if ($mapping === null) {
            return Response::deny();
        }
        try {
            $user = $this->resolveUser();
            if (! $user instanceof Authenticatable) {
                return Response::deny();
            }
            $access = $this->container->make(IdentityAccess::class);
            $principal = $access->principal(true);
            if (! $principal->hasPermission($mapping['permission'])) {
                return Response::deny();
            }
            $access->assertOwner($user);
        } catch (IdentityException) {
            return Response::deny();
        }

        // Deliberately call the required business rule, without Gate/policy before bypasses.
        // No implicit class-argument removal: the method receives exactly user + arguments.
        $policyClass = $mapping['policy'];
        $policy = $this->container->make($policyClass);
        $callback = [$policy, $mapping['method']];
        if (! $policy instanceof $policyClass || ! is_callable($callback)) {
            return Response::deny();
        }
        $result = $callback($user, ...Arr::wrap($arguments));
        $result = $result instanceof Response ? $result : ($result === true ? Response::allow() : Response::deny());
        if ($result->allowed() && ! $principal->hasPermission($mapping['permission'])) {
            $result = Response::deny();
        }
        $this->dispatchGateEvaluatedEvent($user, $ability, Arr::wrap($arguments), $result->allowed());

        return $result;
    }

    /**
     * @param  UnitEnum|string  $ability
     * @param  mixed  $arguments
     */
    public function inspect($ability, $arguments = []): Response
    {
        return $this->registry->owns($this->abilityName($ability))
            ? parent::inspect($ability, $arguments) : $this->inner->inspect($ability, $arguments);
    }

    public function defaultDenialResponse(Response $response): static
    {
        parent::defaultDenialResponse($response);
        $this->inner->defaultDenialResponse($response);

        return $this;
    }

    /** @param mixed $user */
    public function forUser($user): static
    {
        $gate = new self($this->container, $this->inner->forUser($user), $this->registry, fn () => $user);
        $gate->defaultDenialResponse = $this->defaultDenialResponse;

        return $gate;
    }

    /** @param UnitEnum|string|array<array-key, UnitEnum|string> $ability */
    public function has($ability): bool
    {
        return collect(Arr::wrap($ability))->every(fn (UnitEnum|string $name) => $this->registry->owns($this->abilityName($name))
            ? $this->registry->mapping($this->abilityName($name)) !== null : $this->inner->has($name));
    }

    /**
     * @param  UnitEnum|string  $ability
     * @param  callable|array<array-key, mixed>|string  $callback
     */
    public function define($ability, $callback): static
    {
        if (is_array($callback) && isset($callback[0]) && is_string($callback[0])) {
            $method = $callback[1] ?? null;
            if (! is_string($method)) {
                throw new InvalidArgumentException('A class ability callback requires a method name.');
            }
            $callback = $callback[0].'@'.$method;
        }
        if (! is_callable($callback) && ! is_string($callback)) {
            throw new InvalidArgumentException('Callback must be a callable, callback array, or a string.');
        }
        $this->inner->define($ability, $callback);

        return $this;
    }

    /**
     * @param  string  $name
     * @param  string  $class
     * @param  array<string, string>|null  $abilities
     */
    public function resource($name, $class, ?array $abilities = null): static
    {
        $this->inner->resource($name, $class, $abilities);

        return $this;
    }

    /**
     * @param  string  $class
     * @param  string  $policy
     */
    public function policy($class, $policy): static
    {
        $this->inner->policy($class, $policy);

        return $this;
    }

    public function before(callable $callback): static
    {
        $this->inner->before($callback);

        return $this;
    }

    public function after(callable $callback): static
    {
        $this->inner->after($callback);

        return $this;
    }

    /** @param object|string $class */
    public function getPolicyFor($class): mixed
    {
        return $this->inner->getPolicyFor($class);
    }

    /** @return array<array-key, mixed> */
    public function abilities(): array
    {
        return $this->inner->abilities();
    }

    /** @return array<array-key, mixed> */
    public function policies(): array
    {
        return $this->inner->policies();
    }

    public function guessPolicyNamesUsing(callable $callback): static
    {
        $this->inner->guessPolicyNamesUsing($callback);

        return $this;
    }

    /** @param object|string $class */
    public function resolvePolicy($class): mixed
    {
        return $this->inner->resolvePolicy($class);
    }

    /** Laravel stores backed enum abilities using their scalar PHP array key. */
    private function abilityName(UnitEnum|string $ability): string
    {
        if (is_string($ability)) {
            return $ability;
        }
        if ($ability instanceof BackedEnum) {
            return (string) $ability->value;
        }

        return $ability->name;
    }
}
