<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Users\RetainedNativeLifecycle;
use Illuminate\Support\Arr;
use JsonSerializable;
use LogicException;

/** Immutable trusted configuration; never a request, principal or authorization grant. */
final readonly class ConsumerContext implements JsonSerializable
{
    private array $definition;

    public function __construct(private string $name, #[\SensitiveParameter] array $definition, private string $connection)
    {
        $snapshot = ContextDefinition::snapshot($definition);
        if (isset($snapshot['users']) && is_array($snapshot['users'])) {
            $snapshot['users'] += ['protected_fields' => [], 'local_fields' => [], 'readonly_fields' => [], 'lifecycle_policy' => RetainedNativeLifecycle::class, 'identity_projection_epoch' => 1, 'native_group' => null];
        }
        ContextDefinition::consumer($name, $snapshot, $connection);
        $this->definition = $snapshot;
    }

    public function name(): string
    {
        return $this->name;
    }

    public function connection(): string
    {
        return $this->connection;
    }

    public function value(string $key, mixed $default = null): mixed
    {
        return Arr::get($this->definition, $key, $default);
    }

    public function origin(): string
    {
        return $this->definition['origin'];
    }

    public function appOrigin(): string
    {
        return $this->definition['app_origin'];
    }

    public function issuer(): string
    {
        return $this->origin().'/api/auth';
    }

    public function serviceIssuer(): string
    {
        return $this->origin().'/api/service-auth';
    }

    public function applicationId(): string
    {
        return $this->definition['application_id'];
    }

    public function hasBrowser(): bool
    {
        return $this->definition['browser'] !== null;
    }

    public function clientId(): string
    {
        $this->requireBrowser();

        return $this->definition['browser']['client_id'];
    }

    public function credentials(string $plane): array
    {
        if (! in_array($plane, ['browser', 'resource'], true)) {
            throw new IdentityException('invalid_credential_plane');
        }
        $credentials = $this->definition[$plane];
        if ($credentials === null) {
            throw new IdentityException('credential_plane_unavailable');
        }

        return ['id' => $credentials['client_id'], 'secret' => $credentials['client_secret']];
    }

    public function sessionSettings(): array
    {
        $this->requireBrowser();

        return $this->definition['session'];
    }

    public function bindingHash(): string
    {
        return hash('sha256', implode("\0", [$this->issuer(), $this->clientId(), $this->applicationId(), $this->appOrigin(), $this->sessionSettings()['cookie']]));
    }

    public function routeName(string $action): string
    {
        $this->requireBrowser();
        ContextDefinition::require(in_array($action, ['application-contexts', 'application-context.current', 'application-context.select', 'application-context.clear', 'entry', 'login', 'callback', 'contexts', 'context.select', 'logout', 'central-logout', 'signed-out', 'backchannel-logout', 'events', 'delegation.start', 'delegation.callback', 'delegation.stop'], true), 'unknown_consumer_route');

        return 'identity.'.$this->name.'.'.$action;
    }

    private function requireBrowser(): void
    {
        ContextDefinition::require($this->hasBrowser(), 'browser_context_unavailable');
    }

    public function jsonSerialize(): array
    {
        return ['name' => $this->name, 'browser' => $this->hasBrowser()];
    }

    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    public function __serialize(): array
    {
        throw new LogicException('Identity contexts cannot be serialized; persist a local row reference.');
    }

    public function __unserialize(array $data): void
    {
        throw new LogicException('Identity contexts must be constructed from trusted definitions.');
    }
}
