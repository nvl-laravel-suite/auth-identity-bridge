<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use IdentityPlatform\Laravel\Users\NativeLifecyclePolicy;
use IdentityPlatform\Laravel\Users\NativeMappingDefinition;
use IdentityPlatform\Laravel\Users\NativeUserFactory;
use IdentityPlatform\Laravel\Users\NativeUserMapper;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use ReflectionClass;

/** Strict, side-effect-free compilation of cacheable, server-owned definitions.
 *
 * @phpstan-type Credentials array{client_id: non-empty-string, client_secret: non-empty-string}
 * @phpstan-type Browser array{client_id: non-empty-string, client_secret: non-empty-string, redirect_uri: non-empty-string, post_logout_redirect_uri: non-empty-string, id_token_algorithm: 'EdDSA'|'ES256'|'RS256'}
 * @phpstan-type Http array{ca_bundle: non-empty-string|null, max_response_bytes: int}
 * @phpstan-type Routes array{enabled: bool, path_prefix: non-empty-string, guard: non-empty-string, event_uri: non-empty-string, backchannel_logout_uri: non-empty-string}
 * @phpstan-type Session array{cookie: non-empty-string, domain: non-empty-string|null, path: non-empty-string, secure: true, http_only: true, same_site: 'lax'|'none', partitioned: bool, driver: 'array'|'database'|'file'|'redis'|'memcached'|'dynamodb'|'cookie', connection: non-empty-string|null, store: non-empty-string|null, table: non-empty-string, encrypt: bool, lifetime: int, expire_on_close: bool, files: non-empty-string|null, lottery: array{int, int}, prefix: non-empty-string|null, serialization: 'php'|'json', block: bool, block_store: non-empty-string|null, block_lock_seconds: int, block_wait_seconds: int}
 * @phpstan-type Callbacks array{event_secret: non-empty-string|null, event_secret_previous: non-empty-string|null, event_secret_previous_expires_at: non-empty-string|null}
 * @phpstan-type NativeGroup array{name: non-empty-string, writer: non-empty-string, epoch: positive-int}
 * @phpstan-type MappingInput string|array{column: string, transform?: class-string<\IdentityPlatform\Laravel\Users\NativeValueTransform>|null, cast?: string|null, options?: array<array-key, mixed>}
 * @phpstan-type Users array{model: class-string<\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable>|null, factory: class-string<\IdentityPlatform\Laravel\Users\NativeUserFactory>|null, resolver: class-string<\IdentityPlatform\Laravel\Users\IdentityUserResolver>|null, mapper: class-string<\IdentityPlatform\Laravel\Users\NativeUserMapper>|null, fields: array<string, MappingInput>, identity_projection_writer: non-empty-string|null, protected_fields: list<string>, local_fields: list<string>, readonly_fields: list<string>, lifecycle_policy: class-string<\IdentityPlatform\Laravel\Users\NativeLifecyclePolicy>|null, identity_projection_epoch: positive-int, native_group: NativeGroup|null}
 * @phpstan-type Sync array{enabled: bool, provision_missing: bool, import_enabled: bool}
 * @phpstan-type Local array{idle_seconds: int, absolute_seconds: int, transaction_seconds: int}
 * @phpstan-type Delegation array{routes: array<string, string>, operations: array<string, array{write: bool, resource_type: non-empty-string}>}
 * @phpstan-type CommonConsumer array{origin: non-empty-string, app_origin: non-empty-string, application_id: non-empty-string, callbacks: Callbacks, users: Users, sync: Sync, local: Local, delegation: Delegation, lock_store: non-empty-string, http: Http}
 * @phpstan-type BrowserConsumer array{origin: non-empty-string, app_origin: non-empty-string, application_id: non-empty-string, callbacks: Callbacks, users: Users, sync: Sync, local: Local, delegation: Delegation, lock_store: non-empty-string, http: Http, browser: Browser, resource: Credentials|null, session: Session, routes: Routes}
 * @phpstan-type ResourceConsumer array{origin: non-empty-string, app_origin: non-empty-string, application_id: non-empty-string, callbacks: Callbacks, users: Users, sync: Sync, local: Local, delegation: Delegation, lock_store: non-empty-string, http: Http, browser: null, resource: Credentials, session: null, routes: null}
 * @phpstan-type Consumer BrowserConsumer|ResourceConsumer
 * @phpstan-type Target array{origin: non-empty-string, application_id: non-empty-string, base_url: non-empty-string, client_id: non-empty-string, client_secret: non-empty-string, scopes: non-empty-list<non-empty-string>, cache_store: non-empty-string, http: Http}
 */
final class ContextDefinition
{
    /** @phpstan-assert true $condition */
    public static function require(bool $condition, string $code = 'invalid_identity_configuration'): void
    {
        if (! $condition) {
            throw new IdentityException($code);
        }
    }

    /** Rebuild every array to detach PHP references as well as mutable repositories.
     *
     * @return ($value is array ? array<array-key, mixed> : scalar|null)
     */
    public static function snapshot(#[\SensitiveParameter] mixed $value, int $depth = 0): mixed
    {
        self::require($depth <= 32);
        if (is_array($value)) {
            $copy = [];
            foreach ($value as $key => $item) {
                $copy[$key] = self::snapshot($item, $depth + 1);
            }

            return $copy;
        }
        self::require($value === null || is_scalar($value));
        self::require(! is_float($value) || is_finite($value));

        return $value;
    }

    /**
     * @param  list<array-key>  $keys
     *
     * @phpstan-assert =array<array-key, mixed> $value
     */
    public static function keys(#[\SensitiveParameter] mixed $value, array $keys): void
    {
        self::require(is_array($value) && count($value) === count($keys) && array_diff($keys, array_keys($value)) === []);
    }

    /** @phpstan-assert =non-empty-string $value */
    public static function text(#[\SensitiveParameter] mixed $value, int $maximum = 512): void
    {
        self::require(is_string($value) && $value !== '' && strlen($value) <= $maximum && ! preg_match('/[\x00-\x20\x7f]/', $value));
    }

    /** @phpstan-assert =non-empty-string $name */
    public static function name(mixed $name): void
    {
        self::require(is_string($name) && preg_match('/^[A-Za-z][A-Za-z0-9_-]{0,63}$/D', $name) === 1);
    }

    /** @phpstan-assert =non-empty-string $value */
    public static function identifier(#[\SensitiveParameter] mixed $value): void
    {
        self::text($value, 128);
    }

    /** @phpstan-assert =int $value */
    public static function integer(#[\SensitiveParameter] mixed $value, int $min, int $max): void
    {
        self::require(is_int($value) && $value >= $min && $value <= $max);
    }

    /** @phpstan-assert bool $value */
    public static function boolean(#[\SensitiveParameter] mixed $value): void
    {
        self::require(is_bool($value));
    }

    /**
     * @phpstan-assert =non-empty-string $value
     *
     * @return array{scheme: string, host: string, port?: int}
     */
    public static function origin(#[\SensitiveParameter] mixed $value): array
    {
        self::text($value, 2048);
        $parts = parse_url($value);
        self::require(is_array($parts) && ($parts['scheme'] ?? null) === 'https' && isset($parts['host']) && array_diff(array_keys($parts), ['scheme', 'host', 'port']) === []);
        $host = $parts['host'];
        self::require(filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) !== false || (strlen($host) <= 253 && preg_match('/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/D', $host) === 1));
        self::integer($parts['port'] ?? 443, 1, 65535);

        return $parts;
    }

    public static function originKey(string $origin): string
    {
        $parts = self::origin($origin);

        return strtolower($parts['host']).':'.($parts['port'] ?? 443);
    }

    /** @phpstan-assert =non-empty-string $path */
    public static function path(mixed $path): void
    {
        self::text($path, 2048);
        self::require(str_starts_with($path, '/') && ! str_contains($path, '//') && ! preg_match('/[%\\\\?#\x80-\xff]/', $path));
        self::require(preg_match("#\\A/[A-Za-z0-9._~!$&'()*+,;=:@/-]*\\z#", $path) === 1);
        self::require(! array_intersect(explode('/', $path), ['.', '..']));
    }

    public static function withinPath(string $path, string $prefix): bool
    {
        return $prefix === '/' || $path === $prefix || str_starts_with($path, rtrim($prefix, '/').'/');
    }

    /**
     * @phpstan-assert =non-empty-string $value
     *
     * @return array{scheme: string, host: string, port?: int, path?: string}
     */
    public static function url(#[\SensitiveParameter] mixed $value, ?string $origin = null): array
    {
        self::text($value, 4096);
        $parts = parse_url($value);
        self::require(is_array($parts) && isset($parts['scheme'], $parts['host']) && array_diff(array_keys($parts), ['scheme', 'host', 'port', 'path']) === []);
        $actual = $parts['scheme'].'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '');
        self::origin($actual);
        self::path($parts['path'] ?? '/');
        self::require($origin === null || $actual === $origin);

        return $parts;
    }

    /** @phpstan-assert =Credentials $value */
    public static function credentials(#[\SensitiveParameter] mixed $value): void
    {
        self::keys($value, ['client_id', 'client_secret']);
        self::identifier($value['client_id']);
        self::text($value['client_secret'], 8192);
    }

    /** @phpstan-assert =Http $value */
    public static function http(#[\SensitiveParameter] mixed $value): void
    {
        self::keys($value, ['ca_bundle', 'max_response_bytes']);
        if ($value['ca_bundle'] !== null) {
            self::text($value['ca_bundle'], 4096);
            self::require(str_starts_with($value['ca_bundle'], '/') && ! str_contains($value['ca_bundle'], '://'));
        }
        self::integer($value['max_response_bytes'], 1024, 16777216);
    }

    /**
     * @template T of object
     *
     * @param  class-string<T>  $contract
     * @return ReflectionClass<T>|null
     *
     * @phpstan-assert =class-string<T>|null $class
     */
    public static function registeredClass(mixed $class, string $contract, bool $nullable = true): ?ReflectionClass
    {
        if ($class === null && $nullable) {
            return null;
        }
        self::require(is_string($class) && class_exists($class) && is_a($class, $contract, true));
        $reflection = new ReflectionClass($class);
        self::require($reflection->isInstantiable());

        return $reflection;
    }

    /**
     * @param  array<array-key, mixed>  $value
     *
     * @phpstan-assert =Consumer $value
     */
    public static function consumer(string $name, #[\SensitiveParameter] array $value, string $connection): void
    {
        self::name($name);
        self::name($connection);
        self::keys($value, ['origin', 'app_origin', 'application_id', 'browser', 'resource', 'session', 'routes', 'callbacks', 'users', 'sync', 'local', 'delegation', 'lock_store', 'http']);
        self::origin($value['origin']);
        self::origin($value['app_origin']);
        self::identifier($value['application_id']);
        if ($value['resource'] !== null) {
            self::credentials($value['resource']);
        }
        $browser = $value['browser'];
        $session = $value['session'];
        if ($browser !== null) {
            self::keys($browser, ['client_id', 'client_secret', 'redirect_uri', 'post_logout_redirect_uri', 'id_token_algorithm']);
            self::credentials(array_intersect_key($browser, array_flip(['client_id', 'client_secret'])));
            self::require(in_array($browser['id_token_algorithm'], ['EdDSA', 'ES256', 'RS256'], true));
            self::routes($value);
            self::session($session, $value['app_origin']);
            self::require(self::withinPath($value['routes']['path_prefix'], $session['path']));
        } else {
            self::require($value['resource'] !== null && $session === null && $value['routes'] === null);
        }
        self::callbacks($value['callbacks']);
        self::users($value['users'], $connection, $browser !== null);
        self::keys($value['sync'], ['enabled', 'provision_missing', 'import_enabled']);
        foreach ($value['sync'] as $flag) {
            self::boolean($flag);
        }
        self::require(! $value['sync']['import_enabled'] || $value['sync']['enabled']);
        self::require(! $value['sync']['provision_missing'] || ($value['sync']['enabled'] && $value['users']['model'] !== null));
        self::require($browser !== null || ! in_array(true, $value['sync'], true));
        self::keys($value['local'], ['idle_seconds', 'absolute_seconds', 'transaction_seconds']);
        self::integer($value['local']['idle_seconds'], 1, 31536000);
        self::integer($value['local']['absolute_seconds'], $value['local']['idle_seconds'], 31536000);
        self::integer($value['local']['transaction_seconds'], 1, 300);
        if ($browser !== null) {
            self::require($value['local']['idle_seconds'] <= $session['lifetime'] * 60);
        }
        self::delegation($value['delegation']);
        self::require($browser !== null || ($value['delegation']['routes'] === [] && $value['delegation']['operations'] === []));
        self::name($value['lock_store']);
        self::http($value['http']);
    }

    /**
     * @param  array<array-key, mixed>  $value
     *
     * @phpstan-assert =array{routes: Routes, ...} $value
     */
    private static function routes(#[\SensitiveParameter] array $value): void
    {
        $routes = $value['routes'];
        self::keys($routes, ['enabled', 'path_prefix', 'guard', 'event_uri', 'backchannel_logout_uri']);
        self::boolean($routes['enabled']);
        self::name($routes['guard']);
        self::path($routes['path_prefix']);
        self::require($routes['path_prefix'] === '/' || ! str_ends_with($routes['path_prefix'], '/'));
        self::text($value['app_origin'], 2048);
        $browser = $value['browser'];
        self::keys($browser, ['client_id', 'client_secret', 'redirect_uri', 'post_logout_redirect_uri', 'id_token_algorithm']);
        $base = $value['app_origin'].rtrim($routes['path_prefix'], '/');
        if ($routes['enabled']) {
            self::require($browser['redirect_uri'] === $base.'/auth/callback');
            self::require($browser['post_logout_redirect_uri'] === $base.'/signed-out');
        }
        $urls = [$browser['redirect_uri'], $browser['post_logout_redirect_uri'], $routes['event_uri'], $routes['backchannel_logout_uri']];
        $routeKeys = [];
        foreach ($urls as $url) {
            $parts = self::url($url, $value['app_origin']);
            self::require(self::withinPath($parts['path'] ?? '/', $routes['path_prefix']));
            // Laravel trims trailing slashes for route registration and matching.
            // Compare those keys without changing exact protocol endpoint URLs.
            $routeKeys[] = rtrim($parts['path'] ?? '/', '/') ?: '/';
        }
        self::require(count(array_unique($routeKeys)) === count($routeKeys));
        if ($routes['enabled']) {
            $reserved = array_map(fn (string $path): string => rtrim($routes['path_prefix'], '/').$path, ['/auth/application-contexts', '/auth/application-context', '/auth/application-context/clear', '/auth/entry', '/auth/sign-in', '/auth/callback', '/auth/contexts', '/auth/context', '/auth/sign-out', '/auth/central-sign-out', '/signed-out', '/auth/delegation/start', '/auth/delegation/callback', '/auth/delegation/stop']);
            self::require(! in_array($routeKeys[2], $reserved, true) && ! in_array($routeKeys[3], $reserved, true));
        }
    }

    /** @phpstan-assert =Session $session */
    private static function session(#[\SensitiveParameter] mixed $session, string $origin): void
    {
        self::keys($session, ['cookie', 'domain', 'path', 'secure', 'http_only', 'same_site', 'partitioned', 'driver', 'connection', 'store', 'table', 'encrypt', 'lifetime', 'expire_on_close', 'files', 'lottery', 'prefix', 'serialization', 'block', 'block_store', 'block_lock_seconds', 'block_wait_seconds']);
        self::text($session['cookie'], 128);
        self::require(preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/D', $session['cookie']) === 1);
        foreach (['secure', 'http_only', 'partitioned', 'encrypt', 'expire_on_close', 'block'] as $flag) {
            self::boolean($session[$flag]);
        }
        self::require($session['secure'] && $session['http_only'] && in_array($session['same_site'], ['lax', 'none'], true));
        self::path($session['path']);
        self::require($session['path'] === '/' || ! str_ends_with($session['path'], '/'));
        $host = strtolower(self::origin($origin)['host']);
        if ($session['domain'] !== null) {
            self::text($session['domain'], 253);
            self::require($session['domain'] === strtolower($session['domain']) && ! str_starts_with($session['domain'], '.') && str_contains($session['domain'], '.') && ($host === $session['domain'] || str_ends_with($host, '.'.$session['domain'])));
        }
        self::require(! str_starts_with($session['cookie'], '__Host-') || ($session['domain'] === null && $session['path'] === '/'));
        self::require(! $session['partitioned'] || ($session['domain'] === null && $session['same_site'] === 'none'));
        self::require(in_array($session['driver'], ['array', 'database', 'file', 'redis', 'memcached', 'dynamodb', 'cookie'], true));
        foreach (['connection', 'store', 'block_store'] as $key) {
            if ($session[$key] !== null) {
                self::name($session[$key]);
            }
        }
        self::require(! $session['block'] || $session['block_store'] !== null);
        self::require($session['driver'] !== 'database' || $session['connection'] !== null);
        self::require(! in_array($session['driver'], ['redis', 'memcached', 'dynamodb'], true) || $session['store'] !== null);
        self::require($session['driver'] !== 'redis' || $session['connection'] !== null);
        if ($session['files'] !== null) {
            self::text($session['files'], 4096);
            self::require(str_starts_with($session['files'], '/'));
        }
        self::require($session['driver'] !== 'file' || $session['files'] !== null);
        if ($session['prefix'] !== null) {
            self::text($session['prefix'], 255);
        }
        self::require($session['driver'] !== 'redis' || $session['prefix'] !== null);
        self::require(in_array($session['serialization'], ['php', 'json'], true));
        self::require(is_array($session['lottery']) && array_is_list($session['lottery']) && count($session['lottery']) === 2);
        self::integer($session['lottery'][1], 1, 1000000);
        self::integer($session['lottery'][0], 0, $session['lottery'][1]);
        self::integer($session['block_lock_seconds'], 1, 300);
        self::integer($session['block_wait_seconds'], 1, 300);
        self::name($session['table']);
        self::integer($session['lifetime'], 1, 525600);
    }

    /** @phpstan-assert =Callbacks $callbacks */
    private static function callbacks(#[\SensitiveParameter] mixed $callbacks): void
    {
        self::keys($callbacks, ['event_secret', 'event_secret_previous', 'event_secret_previous_expires_at']);
        foreach (['event_secret', 'event_secret_previous'] as $key) {
            if ($callbacks[$key] !== null) {
                self::text($callbacks[$key], 1024);
                self::require(strlen($callbacks[$key]) >= 32);
            }
        }
        self::require(($callbacks['event_secret_previous'] === null) === ($callbacks['event_secret_previous_expires_at'] === null));
        if ($callbacks['event_secret_previous'] !== null) {
            self::require($callbacks['event_secret'] !== null && $callbacks['event_secret'] !== $callbacks['event_secret_previous']);
            $instant = $callbacks['event_secret_previous_expires_at'];
            self::require(is_string($instant) && preg_match('/\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.[0-9]+)?)?Z\z/', $instant, $parts) === 1);
            self::require(checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1]) && (int) $parts[4] < 24 && (int) $parts[5] < 60 && (int) ($parts[6] ?? 0) < 60);
        }
    }

    /** @phpstan-assert =Users $users */
    private static function users(#[\SensitiveParameter] mixed $users, string $connection, bool $browser): void
    {
        self::keys($users, ['model', 'factory', 'resolver', 'mapper', 'fields', 'identity_projection_writer', 'protected_fields', 'local_fields', 'readonly_fields', 'lifecycle_policy', 'identity_projection_epoch', 'native_group']);
        $model = self::registeredClass($users['model'], Model::class);
        $properties = $model?->getDefaultProperties() ?? [];
        if ($model !== null) {
            self::require($model->implementsInterface(Authenticatable::class) && ($properties['connection'] ?? $connection) === $connection);
        }
        self::registeredClass($users['factory'], NativeUserFactory::class);
        self::registeredClass($users['resolver'], IdentityUserResolver::class);
        self::registeredClass($users['mapper'], NativeUserMapper::class);
        self::require(is_array($users['fields']));
        foreach (['protected_fields', 'local_fields', 'readonly_fields'] as $key) {
            self::require(is_array($users[$key]) && array_is_list($users[$key]));
            foreach ($users[$key] as $column) {
                self::require(is_string($column) && preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/D', $column) === 1);
            }
        }
        self::registeredClass($users['lifecycle_policy'], NativeLifecyclePolicy::class);
        self::require(is_int($users['identity_projection_epoch']) && $users['identity_projection_epoch'] > 0);
        if ($users['native_group'] !== null) {
            self::keys($users['native_group'], ['name', 'writer', 'epoch']);
            self::name($users['native_group']['name']);
            self::name($users['native_group']['writer']);
            self::require($model !== null && is_int($users['native_group']['epoch']) && $users['native_group']['epoch'] > 0);
            self::require(! isset($users['fields']['state']));
            self::require(array_intersect(array_keys($users['fields']), ['adminNotes', 'tags', 'lastLoginAt']) === []);
        }
        new NativeMappingDefinition($users, $model ? $model->newInstance() : null);
        if ($browser) {
            self::name($users['identity_projection_writer']);
        } else {
            self::require($users['fields'] === []);
            foreach (['model', 'factory', 'resolver', 'mapper', 'identity_projection_writer'] as $key) {
                self::require($users[$key] === null);
            }
        }
    }

    /** @phpstan-assert =Delegation $delegation */
    private static function delegation(#[\SensitiveParameter] mixed $delegation): void
    {
        self::keys($delegation, ['routes', 'operations']);
        self::require(is_array($delegation['routes']) && is_array($delegation['operations']));
        foreach ($delegation['operations'] as $operation => $registration) {
            self::identifier($operation);
            self::require(! preg_match('/(?:^|\.)(?:security|credentials?|roles?|grants?|clients?|invitations?|global|admin|impersonat|delegat)(?:\.|$)/i', $operation));
            self::require(! in_array($operation, ['users.profile.read', 'users.profile.update', 'users.metadata.read', 'users.metadata.update'], true));
            self::keys($registration, ['write', 'resource_type']);
            self::boolean($registration['write']);
            self::identifier($registration['resource_type']);
        }
        foreach ($delegation['routes'] as $route => $operation) {
            self::identifier($route);
            self::require(is_string($operation) && isset($delegation['operations'][$operation]));
        }
    }

    /**
     * @param  array<array-key, mixed>  $value
     *
     * @phpstan-assert =Target $value
     */
    public static function target(string $name, #[\SensitiveParameter] array $value): void
    {
        self::name($name);
        self::keys($value, ['origin', 'application_id', 'base_url', 'client_id', 'client_secret', 'scopes', 'cache_store', 'http']);
        self::origin($value['origin']);
        self::identifier($value['application_id']);
        self::url($value['base_url']);
        self::credentials(array_intersect_key($value, array_flip(['client_id', 'client_secret'])));
        self::require(is_array($value['scopes']) && array_is_list($value['scopes']) && $value['scopes'] !== [] && count($value['scopes']) <= 250);
        $scopes = [];
        foreach ($value['scopes'] as $scope) {
            self::text($scope, 128);
            self::require(preg_match('/^[a-z][a-z0-9._:-]{1,127}$/D', $scope) === 1 && ! in_array($scope, ['openid', 'profile', 'email', 'offline_access'], true));
            $scopes[] = $scope;
        }
        self::require(count(array_unique($scopes)) === count($value['scopes']));
        self::name($value['cache_store']);
        self::http($value['http']);
    }
}
