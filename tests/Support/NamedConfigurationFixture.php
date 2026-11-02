<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Users\EloquentIdentityUserResolver;
use IdentityPlatform\Laravel\Users\EloquentNativeUserFactory;
use IdentityPlatform\Laravel\Users\EloquentNativeUserMapper;
use Illuminate\Foundation\Auth\User;

class ConfigurationNativeUser extends User {}

class ForeignConnectionUser extends User
{
    protected $connection = 'foreign';
}

trait NamedConfigurationFixture
{
    private function definition(): array
    {
        return ['default_consumer' => 'one', 'connection' => null, 'consumers' => ['one' => $this->consumer()], 'service_targets' => ['reports' => $this->target()]];
    }

    private function consumer(string $origin = 'https://consumer.test', string $prefix = '/'): array
    {
        $base = $origin.rtrim($prefix, '/');

        return [
            'origin' => 'https://identity.test', 'app_origin' => $origin, 'application_id' => 'app-1',
            'browser' => ['client_id' => 'web-1', 'client_secret' => 'synthetic-browser-secret', 'redirect_uri' => $base.'/auth/callback', 'post_logout_redirect_uri' => $base.'/signed-out', 'id_token_algorithm' => 'EdDSA'],
            'resource' => null,
            'session' => ['cookie' => '__Host-one', 'domain' => null, 'path' => '/', 'secure' => true, 'http_only' => true, 'same_site' => 'lax', 'partitioned' => false, 'driver' => 'database', 'connection' => 'sessions', 'store' => null, 'table' => 'sessions', 'encrypt' => true, 'lifetime' => 720, 'expire_on_close' => false, 'files' => null, 'lottery' => [2, 100], 'prefix' => null, 'serialization' => 'php', 'block' => false, 'block_store' => null, 'block_lock_seconds' => 10, 'block_wait_seconds' => 10],
            'routes' => ['enabled' => true, 'path_prefix' => $prefix, 'guard' => 'identity_one', 'event_uri' => $base.'/identity/events', 'backchannel_logout_uri' => $base.'/auth/backchannel-logout'],
            'callbacks' => ['event_secret' => str_repeat('e', 32), 'event_secret_previous' => null, 'event_secret_previous_expires_at' => null],
            'users' => ['model' => ConfigurationNativeUser::class, 'factory' => EloquentNativeUserFactory::class, 'resolver' => EloquentIdentityUserResolver::class, 'mapper' => EloquentNativeUserMapper::class, 'fields' => ['name' => 'name', 'email' => 'email'], 'identity_projection_writer' => 'one'],
            'sync' => ['enabled' => false, 'provision_missing' => false, 'import_enabled' => false],
            'local' => ['idle_seconds' => 1800, 'absolute_seconds' => 43200, 'transaction_seconds' => 300],
            'delegation' => ['routes' => ['documents.show' => 'documents.read'], 'operations' => ['documents.read' => ['write' => false, 'resource_type' => 'documents']]],
            'lock_store' => 'shared', 'http' => ['ca_bundle' => null, 'max_response_bytes' => 131072],
        ];
    }

    private function target(): array
    {
        return ['origin' => 'https://worker-issuer.test', 'application_id' => 'reporting-app', 'base_url' => 'https://reports.test/api', 'client_id' => 'reports-worker', 'client_secret' => 'synthetic-worker-secret', 'scopes' => ['reports.write', 'reports.read'], 'cache_store' => 'shared', 'http' => ['ca_bundle' => null, 'max_response_bytes' => 131072]];
    }

    private function registry(?array $definition = null): ConsumerRegistry
    {
        return new ConsumerRegistry($definition ?? $this->definition(), 'native', ['native', 'sessions', 'foreign'], ['shared'], ['shared']);
    }

    private function twoConsumers(): array
    {
        $definition = $this->definition();
        $definition['consumers']['two'] = $this->consumer('https://second.test');
        $definition['consumers']['two']['browser']['client_id'] = 'web-2';
        $definition['consumers']['two']['session']['cookie'] = '__Host-two';
        $definition['consumers']['two']['routes']['guard'] = 'identity_two';

        return $definition;
    }
}
