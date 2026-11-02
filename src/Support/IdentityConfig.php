<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use IdentityPlatform\Laravel\Users\NativeLifecyclePolicy;
use IdentityPlatform\Laravel\Users\NativeUserFactory;
use IdentityPlatform\Laravel\Users\NativeUserMapper;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/** Compatibility-facing API backed exclusively by one immutable consumer definition.
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
final readonly class IdentityConfig
{
    public function __construct(private ConsumerContext $context) {}

    public function context(): ConsumerContext
    {
        return $this->context;
    }

    /**
     * @template TDefault
     *
     * @param  TDefault  $default
     * @return ($key is 'connection' ? string : ($key is 'origin' ? non-empty-string : ($key is 'app_origin' ? non-empty-string : ($key is 'application_id' ? non-empty-string : ($key is 'lock_store' ? non-empty-string : ($key is 'users' ? Users : ($key is 'users.model' ? class-string<Model&Authenticatable>|null : ($key is 'users.factory' ? class-string<NativeUserFactory>|null : ($key is 'users.resolver' ? class-string<IdentityUserResolver>|null : ($key is 'users.mapper' ? class-string<NativeUserMapper>|null : ($key is 'users.lifecycle_policy' ? class-string<NativeLifecyclePolicy>|null : ($key is 'users.fields' ? array<string, MappingInput> : ($key is 'users.protected_fields' ? list<string> : ($key is 'users.local_fields' ? list<string> : ($key is 'users.readonly_fields' ? list<string> : ($key is 'users.native_group' ? NativeGroup|null : ($key is 'users.identity_projection_epoch' ? positive-int : ($key is 'users.identity_projection_writer' ? non-empty-string|null : ($key is 'users.native_group.name' ? non-empty-string|TDefault : ($key is 'users.native_group.writer' ? non-empty-string|TDefault : ($key is 'users.native_group.epoch' ? positive-int|TDefault : ($key is 'local' ? Local : ($key is 'local.idle_seconds' ? int : ($key is 'local.absolute_seconds' ? int : ($key is 'local.transaction_seconds' ? int : ($key is 'sync' ? Sync : ($key is 'sync.enabled' ? bool : ($key is 'sync.provision_missing' ? bool : ($key is 'sync.import_enabled' ? bool : ($key is 'callbacks' ? Callbacks : ($key is 'callbacks.event_secret' ? non-empty-string|null : ($key is 'callbacks.event_secret_previous' ? non-empty-string|null : ($key is 'callbacks.event_secret_previous_expires_at' ? non-empty-string|null : ($key is 'http' ? Http : ($key is 'http.ca_bundle' ? non-empty-string|null : ($key is 'http.max_response_bytes' ? int : ($key is 'delegation' ? Delegation : ($key is 'delegation.routes' ? array<string, string> : ($key is 'delegation.operations' ? array<string, array{write: bool, resource_type: non-empty-string}> : ($key is 'browser' ? Browser|null : ($key is 'browser.client_id' ? non-empty-string|TDefault : ($key is 'browser.client_secret' ? non-empty-string|TDefault : ($key is 'browser.redirect_uri' ? non-empty-string|TDefault : ($key is 'browser.post_logout_redirect_uri' ? non-empty-string|TDefault : ($key is 'browser.id_token_algorithm' ? 'EdDSA'|'ES256'|'RS256'|TDefault : ($key is 'resource' ? Credentials|null : ($key is 'resource.client_id' ? non-empty-string|TDefault : ($key is 'resource.client_secret' ? non-empty-string|TDefault : ($key is 'routes' ? Routes|null : ($key is 'routes.enabled' ? bool|TDefault : ($key is 'routes.path_prefix' ? non-empty-string|TDefault : ($key is 'routes.guard' ? non-empty-string|TDefault : ($key is 'routes.event_uri' ? non-empty-string|TDefault : ($key is 'routes.backchannel_logout_uri' ? non-empty-string|TDefault : ($key is 'session' ? Session|null : ($key is 'session.cookie' ? non-empty-string|TDefault : ($key is 'session.domain' ? non-empty-string|null|TDefault : ($key is 'session.path' ? non-empty-string|TDefault : ($key is 'session.secure' ? true|TDefault : ($key is 'session.http_only' ? true|TDefault : ($key is 'session.same_site' ? 'lax'|'none'|TDefault : ($key is 'session.partitioned' ? bool|TDefault : ($key is 'session.driver' ? 'array'|'database'|'file'|'redis'|'memcached'|'dynamodb'|'cookie'|TDefault : ($key is 'session.connection' ? non-empty-string|null|TDefault : ($key is 'session.store' ? non-empty-string|null|TDefault : ($key is 'session.table' ? non-empty-string|TDefault : ($key is 'session.encrypt' ? bool|TDefault : ($key is 'session.lifetime' ? int|TDefault : ($key is 'session.expire_on_close' ? bool|TDefault : ($key is 'session.files' ? non-empty-string|null|TDefault : ($key is 'session.lottery' ? array{int, int}|TDefault : ($key is 'session.prefix' ? non-empty-string|null|TDefault : ($key is 'session.serialization' ? 'php'|'json'|TDefault : ($key is 'session.block' ? bool|TDefault : ($key is 'session.block_store' ? non-empty-string|null|TDefault : ($key is 'session.block_lock_seconds' ? int|TDefault : ($key is 'session.block_wait_seconds' ? int|TDefault : mixed)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))
     */
    public function value(string $key, mixed $default = null): mixed
    {
        return $key === 'connection' ? $this->context->connection() : $this->context->value($key, $default);
    }

    public function origin(): string
    {
        return $this->context->origin();
    }

    public function appOrigin(): string
    {
        return $this->context->appOrigin();
    }

    public function issuer(): string
    {
        return $this->context->issuer();
    }

    public function serviceIssuer(): string
    {
        return $this->context->serviceIssuer();
    }

    public function applicationId(): string
    {
        return $this->context->applicationId();
    }

    public function clientId(): string
    {
        return $this->context->clientId();
    }

    /** @return array{id: non-empty-string, secret: non-empty-string} */
    public function credentials(string $plane): array
    {
        return $this->context->credentials($plane);
    }

    public function bindingHash(): string
    {
        return $this->context->bindingHash();
    }

    public function routeName(string $action): string
    {
        return $this->context->routeName($action);
    }

    public function url(string $action): string
    {
        $path = match ($action) {
            'callback' => $this->value('browser.redirect_uri'),
            'signed-out' => $this->value('browser.post_logout_redirect_uri'),
            'events' => $this->value('routes.event_uri'),
            'backchannel-logout' => $this->value('routes.backchannel_logout_uri'),
            default => null,
        };
        if ($path !== null) {
            return $path;
        }
        $suffix = match ($action) {
            'application-contexts' => '/auth/application-contexts', 'application-context.current', 'application-context.select' => '/auth/application-context', 'application-context.clear' => '/auth/application-context/clear',
            'entry' => '/auth/entry', 'login' => '/auth/sign-in', 'contexts' => '/auth/contexts', 'context.select' => '/auth/context',
            'logout' => '/auth/sign-out', 'central-logout' => '/auth/central-sign-out',
            'delegation.start' => '/auth/delegation/start', 'delegation.callback' => '/auth/delegation/callback', 'delegation.stop' => '/auth/delegation/stop',
            default => throw new IdentityException('unknown_consumer_route'),
        };

        $prefix = $this->value('routes.path_prefix');
        if ($prefix === null) {
            throw new IdentityException('browser_context_unavailable');
        }

        return $this->appOrigin().rtrim($prefix, '/').$suffix;
    }
}
