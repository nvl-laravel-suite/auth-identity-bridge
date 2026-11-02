<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use JsonSerializable;
use LogicException;

/** Process-safe registry. Selection is always explicit and never retained. */
final readonly class ConsumerRegistry implements JsonSerializable
{
    /** @var array<string, ConsumerContext> */
    private array $consumers;

    /** @var array<string, ConsumerContext> */
    private array $bindings;

    private ServiceTargetRegistry $serviceTargets;

    private ?string $defaultName;

    private string $connection;

    /**
     * The host explicitly supplies its effective default/known connections and vetted
     * shared, renewable lock stores. No mutable framework repository is retained.
     *
     * @param  array<array-key, mixed>  $configuration
     * @param  list<string>  $connections
     * @param  list<string>  $sharedLockStores
     * @param  list<string>  $cacheStores
     */
    public function __construct(#[\SensitiveParameter] array $configuration, string $defaultConnection, array $connections, array $sharedLockStores, array $cacheStores)
    {
        $configuration = ContextDefinition::snapshot($configuration);
        ContextDefinition::keys($configuration, ['default_consumer', 'connection', 'consumers', 'service_targets']);
        ContextDefinition::name($defaultConnection);
        $connection = $configuration['connection'] ?? $defaultConnection;
        ContextDefinition::name($connection);
        ContextDefinition::require($connection === $defaultConnection && in_array($connection, $connections, true));
        ContextDefinition::require(is_array($configuration['consumers']) && is_array($configuration['service_targets']));
        if ($configuration['consumers'] === []) {
            ContextDefinition::require($configuration['default_consumer'] === null && $configuration['service_targets'] !== []);
        } else {
            ContextDefinition::name($configuration['default_consumer']);
            ContextDefinition::require(array_key_exists($configuration['default_consumer'], $configuration['consumers']));
        }
        $consumers = $bindings = [];
        foreach ($configuration['consumers'] as $name => $definition) {
            ContextDefinition::name($name);
            ContextDefinition::require(is_array($definition));
            $context = new ConsumerContext($name, $definition, $connection);
            ContextDefinition::require(in_array($context->value('lock_store'), $sharedLockStores, true));
            if ($context->hasBrowser()) {
                $binding = $context->bindingHash();
                ContextDefinition::require(! isset($bindings[$binding]), 'duplicate_consumer_binding');
                $bindings[$binding] = $context;
                $session = $context->sessionSettings();
                ContextDefinition::require($session['connection'] === null || in_array($session['connection'], $connections, true));
                ContextDefinition::require($session['store'] === null || in_array($session['store'], $cacheStores, true));
                ContextDefinition::require($session['block_store'] === null || in_array($session['block_store'], $sharedLockStores, true));
                foreach ($consumers as $other) {
                    if ($other->hasBrowser()) {
                        self::distinct($other, $context);
                    }
                }
            }
            $consumers[$name] = $context;
        }
        self::projectionWriters($consumers);
        self::nativeGroups($consumers);
        $this->consumers = $consumers;
        $this->bindings = $bindings;
        $this->serviceTargets = new ServiceTargetRegistry($configuration['service_targets'], $cacheStores);
        $this->defaultName = $configuration['default_consumer'];
        $this->connection = $connection;
    }

    public function get(string $name): ConsumerContext
    {
        return $this->consumers[$name] ?? throw new IdentityException('unknown_consumer');
    }

    public function byBinding(string $binding): ConsumerContext
    {
        return $this->bindings[$binding] ?? throw new IdentityException('unknown_consumer_binding');
    }

    /** Match only exact trusted HTTPS authority and unambiguous server-owned path prefixes. */
    public function forOriginAndPath(string $origin, string $path): ConsumerContext
    {
        $authority = ContextDefinition::originKey($origin);
        $path = self::requestPath($path);
        foreach ($this->consumers as $context) {
            if (! $context->hasBrowser() || $context->value('routes.enabled') !== true || ContextDefinition::originKey($context->appOrigin()) !== $authority) {
                continue;
            }
            $prefix = $context->value('routes.path_prefix');
            ContextDefinition::require($prefix !== null, 'unknown_consumer_route');
            if (ContextDefinition::withinPath($path, $prefix)) {
                return $context;
            }
        }
        throw new IdentityException('unknown_consumer_route');
    }

    /** Decode once as Laravel's URI validator does; strict config paths remain unchanged. */
    public static function requestPath(string $path): string
    {
        ContextDefinition::require(strlen($path) <= 8192 && preg_match('/%(?![0-9a-fA-F]{2})/', $path) !== 1, 'unknown_consumer_route');
        $decoded = rawurldecode($path);
        ContextDefinition::require(mb_check_encoding($decoded, 'UTF-8') && str_starts_with($decoded, '/') && ! str_contains($decoded, '//') && ! str_contains($decoded, '\\') && ! preg_match('/[\x00-\x1f\x7f]/', $decoded) && ! array_intersect(explode('/', $decoded), ['.', '..']), 'unknown_consumer_route');

        return $decoded;
    }

    public function identityProjectionWriter(string $consumer): ConsumerContext
    {
        $context = $this->get($consumer);
        ContextDefinition::require($context->hasBrowser(), 'browser_context_unavailable');

        $writer = $context->value('users.identity_projection_writer');
        ContextDefinition::require($writer !== null, 'invalid_identity_projection_writer');

        return $this->get($writer);
    }

    public function serviceTargets(): ServiceTargetRegistry
    {
        return $this->serviceTargets;
    }

    public function defaultName(): ?string
    {
        return $this->defaultName;
    }

    public function connection(): string
    {
        return $this->connection;
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_keys($this->consumers);
    }

    /** @param array<string, ConsumerContext> $consumers */
    private static function projectionWriters(array $consumers): void
    {
        $writers = [];
        foreach ($consumers as $context) {
            if (! $context->hasBrowser()) {
                continue;
            }
            $writerName = $context->value('users.identity_projection_writer');
            ContextDefinition::require($writerName !== null, 'invalid_identity_projection_writer');
            $writer = $consumers[$writerName] ?? null;
            ContextDefinition::require($writer !== null && $writer->hasBrowser() && $writer->issuer() === $context->issuer(), 'invalid_identity_projection_writer');
            ContextDefinition::require(! isset($writers[$context->issuer()]) || $writers[$context->issuer()] === $writerName, 'invalid_identity_projection_writer');
            ContextDefinition::require($context->value('users.identity_projection_epoch') === $writer->value('users.identity_projection_epoch'), 'invalid_identity_projection_writer');
            $writers[$context->issuer()] = $writerName;
        }
    }

    /** @param array<string, ConsumerContext> $consumers */
    private static function nativeGroups(array $consumers): void
    {
        foreach ($consumers as $context) {
            $group = $context->value('users.native_group');
            if ($group === null) {
                continue;
            }
            $writer = $consumers[$group['writer']] ?? null;
            ContextDefinition::require($writer !== null && $writer->issuer() === $context->issuer() && $writer->value('users.native_group') === $group, 'invalid_native_projection_writer');
            $nativeClass = $context->value('users.model');
            $otherClass = $writer->value('users.model');
            ContextDefinition::require($nativeClass !== null && $otherClass !== null, 'invalid_native_projection_writer');
            $native = new $nativeClass;
            $other = new $otherClass;
            ContextDefinition::require($native->getTable() === $other->getTable() && $native->getConnectionName() === $other->getConnectionName(), 'invalid_native_projection_writer');
            foreach ($consumers as $peer) {
                if ($peer->value('users.native_group.name') === $group['name']) {
                    ContextDefinition::require($peer->value('users.native_group') === $group && $peer->issuer() === $context->issuer(), 'invalid_native_projection_writer');
                }
            }
        }
    }

    private static function distinct(ConsumerContext $one, ConsumerContext $two): void
    {
        $first = $one->sessionSettings();
        $second = $two->sessionSettings();
        $firstHost = strtolower(ContextDefinition::origin($one->appOrigin())['host']);
        $secondHost = strtolower(ContextDefinition::origin($two->appOrigin())['host']);
        if ($first['cookie'] === $second['cookie'] && self::cookieDomainsOverlap($firstHost, $first['domain'], $secondHost, $second['domain']) && (ContextDefinition::withinPath($first['path'], $second['path']) || ContextDefinition::withinPath($second['path'], $first['path']))) {
            throw new IdentityException('consumer_cookie_collision');
        }
        ContextDefinition::require($one->value('routes.guard') !== $two->value('routes.guard'), 'ambiguous_consumer_guard');
        if (ContextDefinition::originKey($one->appOrigin()) === ContextDefinition::originKey($two->appOrigin())) {
            $firstPath = $one->value('routes.path_prefix');
            $secondPath = $two->value('routes.path_prefix');
            ContextDefinition::require($firstPath !== null && $secondPath !== null, 'ambiguous_consumer_routes');
            ContextDefinition::require(! ContextDefinition::withinPath($firstPath, $secondPath) && ! ContextDefinition::withinPath($secondPath, $firstPath), 'ambiguous_consumer_routes');
        }
    }

    private static function cookieDomainsOverlap(string $firstHost, ?string $firstDomain, string $secondHost, ?string $secondDomain): bool
    {
        if ($firstDomain === null && $secondDomain === null) {
            return $firstHost === $secondHost;
        }
        if ($firstDomain === null) {
            return $firstHost === $secondDomain || str_ends_with($firstHost, '.'.$secondDomain);
        }
        if ($secondDomain === null) {
            return $secondHost === $firstDomain || str_ends_with($secondHost, '.'.$firstDomain);
        }

        return $firstDomain === $secondDomain || str_ends_with($firstDomain, '.'.$secondDomain) || str_ends_with($secondDomain, '.'.$firstDomain);
    }

    /** @return array{consumers: list<string>, service_targets: list<string>} */
    public function jsonSerialize(): array
    {
        return ['consumers' => $this->names(), 'service_targets' => $this->serviceTargets->names()];
    }

    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    public function __serialize(): array
    {
        throw new LogicException('Consumer registries cannot be serialized.');
    }

    /** @param array<array-key, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new LogicException('Consumer registries must be constructed from trusted definitions.');
    }
}
