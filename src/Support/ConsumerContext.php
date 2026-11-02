<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use IdentityPlatform\Laravel\Users\NativeLifecyclePolicy;
use IdentityPlatform\Laravel\Users\NativeUserFactory;
use IdentityPlatform\Laravel\Users\NativeUserMapper;
use IdentityPlatform\Laravel\Users\RetainedNativeLifecycle;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr;
use JsonSerializable;
use LogicException;

/** Immutable trusted configuration; never a request, principal or authorization grant.
 *
 * @phpstan-import-type Credentials from ContextDefinition
 * @phpstan-import-type Browser from ContextDefinition
 * @phpstan-import-type Http from ContextDefinition
 * @phpstan-import-type Routes from ContextDefinition
 * @phpstan-import-type Session from ContextDefinition
 * @phpstan-import-type Callbacks from ContextDefinition
 * @phpstan-import-type NativeGroup from ContextDefinition
 * @phpstan-import-type MappingInput from ContextDefinition
 * @phpstan-import-type Users from ContextDefinition
 * @phpstan-import-type Sync from ContextDefinition
 * @phpstan-import-type Local from ContextDefinition
 * @phpstan-import-type Delegation from ContextDefinition
 * @phpstan-import-type BrowserConsumer from ContextDefinition
 * @phpstan-import-type Consumer from ContextDefinition
 */
final readonly class ConsumerContext implements JsonSerializable
{
    /** @var Consumer */
    private array $definition;

    /** @param array<array-key, mixed> $definition */
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

    /**
     * @template TDefault
     *
     * @param  TDefault  $default
     * @return ($key is 'origin' ? non-empty-string : ($key is 'app_origin' ? non-empty-string : ($key is 'application_id' ? non-empty-string : ($key is 'lock_store' ? non-empty-string : ($key is 'users' ? Users : ($key is 'users.model' ? class-string<Model&Authenticatable>|null : ($key is 'users.factory' ? class-string<NativeUserFactory>|null : ($key is 'users.resolver' ? class-string<IdentityUserResolver>|null : ($key is 'users.mapper' ? class-string<NativeUserMapper>|null : ($key is 'users.lifecycle_policy' ? class-string<NativeLifecyclePolicy>|null : ($key is 'users.fields' ? array<string, MappingInput> : ($key is 'users.protected_fields' ? list<string> : ($key is 'users.local_fields' ? list<string> : ($key is 'users.readonly_fields' ? list<string> : ($key is 'users.native_group' ? NativeGroup|null : ($key is 'users.identity_projection_epoch' ? positive-int : ($key is 'users.identity_projection_writer' ? non-empty-string|null : ($key is 'users.native_group.name' ? non-empty-string|TDefault : ($key is 'users.native_group.writer' ? non-empty-string|TDefault : ($key is 'users.native_group.epoch' ? positive-int|TDefault : ($key is 'local' ? Local : ($key is 'local.idle_seconds' ? int : ($key is 'local.absolute_seconds' ? int : ($key is 'local.transaction_seconds' ? int : ($key is 'sync' ? Sync : ($key is 'sync.enabled' ? bool : ($key is 'sync.provision_missing' ? bool : ($key is 'sync.import_enabled' ? bool : ($key is 'callbacks' ? Callbacks : ($key is 'callbacks.event_secret' ? non-empty-string|null : ($key is 'callbacks.event_secret_previous' ? non-empty-string|null : ($key is 'callbacks.event_secret_previous_expires_at' ? non-empty-string|null : ($key is 'http' ? Http : ($key is 'http.ca_bundle' ? non-empty-string|null : ($key is 'http.max_response_bytes' ? int : ($key is 'delegation' ? Delegation : ($key is 'delegation.routes' ? array<string, string> : ($key is 'delegation.operations' ? array<string, array{write: bool, resource_type: non-empty-string}> : ($key is 'browser' ? Browser|null : ($key is 'browser.client_id' ? non-empty-string|TDefault : ($key is 'browser.client_secret' ? non-empty-string|TDefault : ($key is 'browser.redirect_uri' ? non-empty-string|TDefault : ($key is 'browser.post_logout_redirect_uri' ? non-empty-string|TDefault : ($key is 'browser.id_token_algorithm' ? 'EdDSA'|'ES256'|'RS256'|TDefault : ($key is 'resource' ? Credentials|null : ($key is 'resource.client_id' ? non-empty-string|TDefault : ($key is 'resource.client_secret' ? non-empty-string|TDefault : ($key is 'routes' ? Routes|null : ($key is 'routes.enabled' ? bool|TDefault : ($key is 'routes.path_prefix' ? non-empty-string|TDefault : ($key is 'routes.guard' ? non-empty-string|TDefault : ($key is 'routes.event_uri' ? non-empty-string|TDefault : ($key is 'routes.backchannel_logout_uri' ? non-empty-string|TDefault : ($key is 'session' ? Session|null : ($key is 'session.cookie' ? non-empty-string|TDefault : ($key is 'session.domain' ? non-empty-string|null|TDefault : ($key is 'session.path' ? non-empty-string|TDefault : ($key is 'session.secure' ? true|TDefault : ($key is 'session.http_only' ? true|TDefault : ($key is 'session.same_site' ? 'lax'|'none'|TDefault : ($key is 'session.partitioned' ? bool|TDefault : ($key is 'session.driver' ? 'array'|'database'|'file'|'redis'|'memcached'|'dynamodb'|'cookie'|TDefault : ($key is 'session.connection' ? non-empty-string|null|TDefault : ($key is 'session.store' ? non-empty-string|null|TDefault : ($key is 'session.table' ? non-empty-string|TDefault : ($key is 'session.encrypt' ? bool|TDefault : ($key is 'session.lifetime' ? int|TDefault : ($key is 'session.expire_on_close' ? bool|TDefault : ($key is 'session.files' ? non-empty-string|null|TDefault : ($key is 'session.lottery' ? array{int, int}|TDefault : ($key is 'session.prefix' ? non-empty-string|null|TDefault : ($key is 'session.serialization' ? 'php'|'json'|TDefault : ($key is 'session.block' ? bool|TDefault : ($key is 'session.block_store' ? non-empty-string|null|TDefault : ($key is 'session.block_lock_seconds' ? int|TDefault : ($key is 'session.block_wait_seconds' ? int|TDefault : mixed))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))
     */
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

    /** @return array{id: non-empty-string, secret: non-empty-string} */
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

    /** @return Session */
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

    /** @phpstan-assert BrowserConsumer $this->definition */
    private function requireBrowser(): void
    {
        ContextDefinition::require($this->hasBrowser(), 'browser_context_unavailable');
    }

    /** @return array{name: string, browser: bool} */
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

    /** @param array<array-key, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new LogicException('Identity contexts must be constructed from trusted definitions.');
    }
}
