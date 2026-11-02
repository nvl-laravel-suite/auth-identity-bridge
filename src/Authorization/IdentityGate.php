<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use Illuminate\Auth\Access\Gate;
use Illuminate\Auth\Access\Response;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Arr;

use function Illuminate\Support\enum_value;

/** Inherit framework check/inspect/authorize; keep the host Gate for local abilities. */
final class IdentityGate extends Gate
{
    public function __construct(Container $container, private GateContract $inner, private AbilityRegistry $registry, callable $userResolver)
    {
        parent::__construct($container, $userResolver);
    }

    public function raw($ability, $arguments = [])
    {
        $ability = enum_value($ability);
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
        $policy = $this->container->make($mapping['policy']);
        $result = $policy->{$mapping['method']}($user, ...Arr::wrap($arguments));
        $result = $result instanceof Response ? $result : ($result === true ? Response::allow() : Response::deny());
        if ($result->allowed() && ! $principal->hasPermission($mapping['permission'])) {
            $result = Response::deny();
        }
        $this->dispatchGateEvaluatedEvent($user, $ability, Arr::wrap($arguments), $result);

        return $result;
    }

    public function inspect($ability, $arguments = [])
    {
        return $this->registry->owns(enum_value($ability))
            ? parent::inspect($ability, $arguments) : $this->inner->inspect($ability, $arguments);
    }

    public function defaultDenialResponse(Response $response)
    {
        parent::defaultDenialResponse($response);
        $this->inner->defaultDenialResponse($response);

        return $this;
    }

    public function forUser($user)
    {
        $gate = new self($this->container, $this->inner->forUser($user), $this->registry, fn () => $user);
        $gate->defaultDenialResponse = $this->defaultDenialResponse;

        return $gate;
    }

    public function has($ability)
    {
        return collect(Arr::wrap($ability))->every(fn ($name) => $this->registry->owns(enum_value($name))
            ? $this->registry->mapping(enum_value($name)) !== null : $this->inner->has($name));
    }

    public function define($ability, $callback)
    {
        $this->inner->define($ability, $callback);

        return $this;
    }

    public function resource($name, $class, ?array $abilities = null)
    {
        $this->inner->resource($name, $class, $abilities);

        return $this;
    }

    public function policy($class, $policy)
    {
        $this->inner->policy($class, $policy);

        return $this;
    }

    public function before(callable $callback)
    {
        $this->inner->before($callback);

        return $this;
    }

    public function after(callable $callback)
    {
        $this->inner->after($callback);

        return $this;
    }

    public function getPolicyFor($class)
    {
        return $this->inner->getPolicyFor($class);
    }

    public function abilities()
    {
        return $this->inner->abilities();
    }

    public function policies()
    {
        return $this->inner->policies();
    }

    public function guessPolicyNamesUsing(callable $callback)
    {
        $this->inner->guessPolicyNamesUsing($callback);

        return $this;
    }

    public function resolvePolicy($class)
    {
        return $this->inner->resolvePolicy($class);
    }
}
