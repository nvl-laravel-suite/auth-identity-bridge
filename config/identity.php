<?php

declare(strict_types=1);

use IdentityPlatform\Laravel\Users\EloquentIdentityUserResolver;
use IdentityPlatform\Laravel\Users\EloquentNativeUserFactory;
use IdentityPlatform\Laravel\Users\EloquentNativeUserMapper;
use IdentityPlatform\Laravel\Users\RetainedNativeLifecycle;
use Illuminate\Support\Str;

return [
    'default_consumer' => 'default',
    'connection' => env('IDENTITY_DB_CONNECTION'),
    'consumers' => [
        'default' => [
            'origin' => env('IDENTITY_ORIGIN'), 'app_origin' => env('APP_URL'), 'application_id' => env('IDENTITY_APPLICATION_ID'),
            'browser' => [
                'client_id' => env('IDENTITY_CLIENT_ID'), 'client_secret' => env('IDENTITY_CLIENT_SECRET'),
                'redirect_uri' => env('IDENTITY_REDIRECT_URI', rtrim((string) env('APP_URL'), '/').'/auth/callback'),
                'post_logout_redirect_uri' => env('IDENTITY_LOGOUT_REDIRECT_URI', rtrim((string) env('APP_URL'), '/').'/signed-out'),
                'id_token_algorithm' => env('IDENTITY_ID_TOKEN_ALGORITHM', 'EdDSA'),
            ],
            'resource' => env('IDENTITY_RESOURCE_CLIENT_ID') === null && env('IDENTITY_RESOURCE_CLIENT_SECRET') === null ? null : ['client_id' => env('IDENTITY_RESOURCE_CLIENT_ID'), 'client_secret' => env('IDENTITY_RESOURCE_CLIENT_SECRET')],
            'session' => [
                'cookie' => env('SESSION_COOKIE', Str::slug((string) env('APP_NAME', 'laravel')).'-session'),
                'domain' => env('SESSION_DOMAIN'), 'path' => env('SESSION_PATH', '/'),
                'secure' => env('SESSION_SECURE_COOKIE', true), 'http_only' => env('SESSION_HTTP_ONLY', true),
                'same_site' => env('SESSION_SAME_SITE', 'lax'), 'partitioned' => env('SESSION_PARTITIONED_COOKIE', false),
                'driver' => env('SESSION_DRIVER', 'database'),
                'connection' => env('SESSION_CONNECTION', env('DB_CONNECTION', 'sqlite')),
                'store' => env('SESSION_STORE'), 'table' => env('SESSION_TABLE', 'sessions'),
                'encrypt' => env('SESSION_ENCRYPT', false), 'lifetime' => (int) env('SESSION_LIFETIME', 120),
                'expire_on_close' => env('SESSION_EXPIRE_ON_CLOSE', false), 'files' => storage_path('framework/sessions'),
                'lottery' => [2, 100], 'prefix' => env('SESSION_PREFIX'), 'serialization' => 'json',
                'block' => false, 'block_store' => null, 'block_lock_seconds' => 10, 'block_wait_seconds' => 10,
            ],
            'routes' => ['enabled' => true, 'path_prefix' => '/', 'guard' => 'identity',
                'event_uri' => rtrim((string) env('APP_URL'), '/').'/identity/events',
                'backchannel_logout_uri' => rtrim((string) env('APP_URL'), '/').'/auth/backchannel-logout'],
            'callbacks' => ['event_secret' => env('IDENTITY_EVENT_SECRET'), 'event_secret_previous' => env('IDENTITY_EVENT_SECRET_PREVIOUS'), 'event_secret_previous_expires_at' => env('IDENTITY_EVENT_SECRET_PREVIOUS_EXPIRES_AT')],
            'users' => ['model' => null, 'factory' => EloquentNativeUserFactory::class, 'resolver' => EloquentIdentityUserResolver::class, 'mapper' => EloquentNativeUserMapper::class, 'fields' => [], 'identity_projection_writer' => 'default', 'identity_projection_epoch' => 1, 'native_group' => null, 'protected_fields' => [], 'local_fields' => [], 'readonly_fields' => [], 'lifecycle_policy' => RetainedNativeLifecycle::class],
            'sync' => ['enabled' => false, 'provision_missing' => false, 'import_enabled' => false],
            'local' => ['idle_seconds' => 1800, 'absolute_seconds' => 43200, 'transaction_seconds' => 300],
            'delegation' => ['routes' => [], 'operations' => []],
            'lock_store' => env('IDENTITY_LOCK_STORE', env('CACHE_STORE', 'database')),
            'http' => ['ca_bundle' => env('IDENTITY_CA_BUNDLE'), 'max_response_bytes' => 131072],
        ],
    ],
    'service_targets' => env('IDENTITY_SERVICE_CLIENT_ID') === null && env('IDENTITY_SERVICE_CLIENT_SECRET') === null ? [] : [
        'demo' => [
            'origin' => env('IDENTITY_ORIGIN'), 'application_id' => env('IDENTITY_APPLICATION_ID'),
            'base_url' => rtrim((string) env('APP_URL'), '/').'/api',
            'client_id' => env('IDENTITY_SERVICE_CLIENT_ID'), 'client_secret' => env('IDENTITY_SERVICE_CLIENT_SECRET'),
            'scopes' => array_values(array_filter(explode(' ', (string) env('IDENTITY_SERVICE_SCOPES', '')))),
            'cache_store' => env('CACHE_STORE', 'database'),
            'http' => ['ca_bundle' => env('IDENTITY_CA_BUNDLE'), 'max_response_bytes' => 131072],
        ],
    ],
];
