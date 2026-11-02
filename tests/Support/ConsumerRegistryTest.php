<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

require_once __DIR__.'/NamedConfigurationFixture.php';

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ConsumerRegistryTest extends TestCase
{
    use NamedConfigurationFixture;

    protected function setUp(): void
    {
        $this->assertTrue(class_exists(ConsumerRegistry::class), 'Immutable named registry is missing');
    }

    public function test_binding_preserves_the_existing_five_values_through_rename_and_secret_rotation(): void
    {
        $definition = $this->definition();
        $legacy = hash('sha256', implode("\0", ['https://identity.test/api/auth', 'web-1', 'app-1', 'https://consumer.test', '__Host-one']));
        $original = $this->registry($definition)->get('one')->bindingHash();
        $this->assertSame($legacy, $original);
        $renamed = $definition['consumers']['one'];
        $renamed['browser']['client_secret'] = 'rotated-synthetic';
        $renamed['users']['identity_projection_writer'] = 'renamed';
        $definition['default_consumer'] = 'renamed';
        $definition['consumers'] = ['renamed' => $renamed];
        $this->assertSame($original, $this->registry($definition)->get('renamed')->bindingHash());
        $definition['consumers']['renamed']['session']['cookie'] = '__Host-changed';
        $this->assertNotSame($original, $this->registry($definition)->get('renamed')->bindingHash());
    }

    public function test_existing_context_is_a_snapshot_even_when_input_arrays_contain_references(): void
    {
        $definition = $this->definition();
        $cookie = '__Host-one';
        $secret = 'original-synthetic';
        $definition['consumers']['one']['session']['cookie'] = &$cookie;
        $definition['consumers']['one']['browser']['client_secret'] = &$secret;
        $context = $this->registry($definition)->get('one');
        $cookie = '__Host-mutated';
        $secret = 'mutated';
        $definition['consumers']['one']['origin'] = 'https://mutated.test';
        $settings = $context->sessionSettings();
        $settings['cookie'] = 'also-mutated';
        $this->assertSame('__Host-one', $context->sessionSettings()['cookie']);
        $this->assertSame('original-synthetic', $context->credentials('browser')['secret']);
        $this->assertSame('https://identity.test/api/auth', $context->issuer());
        $this->assertSame('native', $context->connection());
        $this->assertSame('sessions', $context->sessionSettings()['connection']);
    }

    public function test_known_names_bindings_routes_and_projection_writer_resolve_independently(): void
    {
        $registry = $this->registry($this->twoConsumers());
        $one = $registry->get('one');
        $two = $registry->get('two');
        $this->assertSame($one, $registry->byBinding($one->bindingHash()));
        $this->assertSame($two, $registry->byBinding($two->bindingHash()));
        $this->assertSame($one, $registry->forOriginAndPath('https://consumer.test', '/documents/1'));
        $this->assertSame($two, $registry->forOriginAndPath('https://second.test', '/auth/callback'));
        $this->assertSame('identity.two.callback', $two->routeName('callback'));
        $this->assertSame($one->bindingHash(), $registry->identityProjectionWriter('two')->bindingHash());
    }

    #[DataProvider('unknownSelections')]
    public function test_unknown_selection_never_falls_back_to_default(string $method, array $arguments): void
    {
        $this->expectException(IdentityException::class);
        $this->registry()->$method(...$arguments);
    }

    public static function unknownSelections(): array
    {
        return [['get', ['missing']], ['byBinding', [str_repeat('0', 64)]], ['forOriginAndPath', ['https://wrong.test', '/auth/callback']], ['forOriginAndPath', ['https://consumer.test:444', '/']], ['forOriginAndPath', ['http://consumer.test', '/']]];
    }

    public function test_duplicate_bindings_are_rejected_even_when_names_and_secrets_differ(): void
    {
        $definition = $this->definition();
        $definition['consumers']['two'] = $definition['consumers']['one'];
        $definition['consumers']['two']['browser']['client_secret'] = 'rotated';
        $this->expectExceptionObject(new IdentityException('duplicate_consumer_binding'));
        $this->registry($definition);
    }

    public function test_disjoint_paths_on_one_origin_are_explicit_and_segment_bound(): void
    {
        $definition = $this->twoConsumers();
        $definition['consumers']['one'] = $this->consumer('https://consumer.test', '/one');
        $definition['consumers']['two'] = $this->consumer('https://consumer.test', '/two');
        $definition['consumers']['two']['session']['cookie'] = '__Host-two';
        $definition['consumers']['two']['routes']['guard'] = 'identity_two';
        $registry = $this->registry($definition);
        $this->assertSame('two', $registry->forOriginAndPath('https://consumer.test', '/two/documents')->name());
        $this->expectException(IdentityException::class);
        $registry->forOriginAndPath('https://consumer.test', '/twosome');
    }

    public function test_nested_trusted_paths_are_rejected_instead_of_longest_prefix_guessing(): void
    {
        $definition = $this->twoConsumers();
        $definition['consumers']['two'] = $this->consumer('https://consumer.test', '/nested');
        $definition['consumers']['two']['session']['cookie'] = '__Host-two';
        $definition['consumers']['two']['routes']['guard'] = 'identity_two';
        $this->expectExceptionObject(new IdentityException('ambiguous_consumer_routes'));
        $this->registry($definition);
    }

    #[DataProvider('cookieScopes')]
    public function test_cookie_scope_collisions_include_domain_path_and_ignore_port(string $secondOrigin, ?string $firstDomain, string $firstPath, string $secondPath, bool $collision): void
    {
        $definition = $this->twoConsumers();
        $definition['consumers']['two'] = $this->consumer($secondOrigin);
        $definition['consumers']['two']['routes']['guard'] = 'identity_two';
        foreach (['one', 'two'] as $name) {
            $definition['consumers'][$name]['session']['cookie'] = 'shared_name';
        }
        $definition['consumers']['one']['session']['domain'] = $firstDomain;
        $definition['consumers']['one']['session']['path'] = $firstPath;
        $definition['consumers']['two']['session']['path'] = $secondPath;
        if ($collision) {
            $this->expectExceptionObject(new IdentityException('consumer_cookie_collision'));
        }
        $registry = $this->registry($definition);
        if (! $collision) {
            $this->assertNotSame($registry->get('one')->bindingHash(), $registry->get('two')->bindingHash());
        }
    }

    public static function cookieScopes(): array
    {
        return [
            ['https://second.test', null, '/', '/', false],
            ['https://child.consumer.test', 'consumer.test', '/', '/', true],
            ['https://child.consumer.test', null, '/', '/', false],
            ['https://consumer.test:8443', null, '/', '/', true],
        ];
    }

    public function test_definitions_survive_config_cache_export_and_contexts_do_not_serialize_credentials(): void
    {
        $definition = $this->definition();
        $cached = eval('return '.var_export($definition, true).';');
        $context = $this->registry($cached)->get('one');
        $this->assertSame($this->registry()->get('one')->bindingHash(), $context->bindingHash());
        $this->assertStringNotContainsString('synthetic-browser-secret', json_encode($context, JSON_THROW_ON_ERROR));
        ob_start();
        var_dump($context, $this->registry());
        $debug = ob_get_clean();
        $this->assertStringNotContainsString('synthetic-browser-secret', $debug);
        $this->assertStringNotContainsString('synthetic-worker-secret', $debug);
        $this->expectException(\LogicException::class);
        serialize($context);
    }

    public function test_resource_verifier_is_optional_and_cannot_fall_back_to_browser(): void
    {
        $this->expectExceptionObject(new IdentityException('credential_plane_unavailable'));
        $this->registry()->get('one')->credentials('resource');
    }

    public function test_explicit_resource_verifier_uses_its_own_credentials(): void
    {
        $definition = $this->definition();
        $definition['consumers']['one']['resource'] = ['client_id' => 'verifier', 'client_secret' => 'synthetic-resource'];
        $this->assertSame('verifier', $this->registry($definition)->get('one')->credentials('resource')['id']);
    }

    public function test_resource_only_context_needs_no_browser_and_has_no_persisted_browser_binding(): void
    {
        $definition = $this->definition();
        $consumer = &$definition['consumers']['one'];
        $consumer['browser'] = $consumer['session'] = $consumer['routes'] = null;
        $consumer['resource'] = ['client_id' => 'resource-only', 'client_secret' => 'synthetic-resource'];
        $consumer['users'] = ['model' => null, 'factory' => null, 'resolver' => null, 'mapper' => null, 'fields' => [], 'identity_projection_writer' => null];
        $consumer['delegation'] = ['operations' => [], 'routes' => []];
        $consumer['users'] = array_reverse($consumer['users'], true);
        $registry = $this->registry($definition);
        $this->assertSame('resource-only', $registry->get('one')->credentials('resource')['id']);
        $this->assertFalse($registry->get('one')->hasBrowser());
        $this->expectExceptionObject(new IdentityException('browser_context_unavailable'));
        $registry->get('one')->bindingHash();
    }

    public function test_disjoint_cookie_paths_on_one_host_do_not_collide(): void
    {
        $definition = $this->twoConsumers();
        foreach (['one', 'two'] as $name) {
            $definition['consumers'][$name] = $this->consumer('https://consumer.test', '/'.$name);
            $definition['consumers'][$name]['browser']['client_id'] = 'web-'.$name;
            $definition['consumers'][$name]['session']['cookie'] = 'same_name';
            $definition['consumers'][$name]['session']['path'] = '/'.$name;
            $definition['consumers'][$name]['routes']['guard'] = 'identity_'.$name;
        }
        $registry = $this->registry($definition);
        $this->assertSame('one', $registry->forOriginAndPath('https://consumer.test', '/one/auth/callback')->name());
        $this->assertSame('two', $registry->forOriginAndPath('https://consumer.test', '/two/auth/callback')->name());
    }

    public function test_cookie_must_cover_the_selected_application_paths(): void
    {
        $definition = $this->definition();
        $definition['consumers']['one']['session']['cookie'] = 'ordinary_name';
        $definition['consumers']['one']['session']['path'] = '/narrow';
        $this->expectException(IdentityException::class);
        $this->registry($definition);
    }

    public function test_valid_rotation_uses_existing_utc_instant_contract_and_snapshots_framework_settings(): void
    {
        $definition = $this->definition();
        $definition['consumers']['one']['callbacks']['event_secret_previous'] = str_repeat('p', 32);
        $definition['consumers']['one']['callbacks']['event_secret_previous_expires_at'] = '2026-11-02T12:00:00Z';
        $context = $this->registry($definition)->get('one');
        $definition['consumers']['one']['session']['lottery'] = [1, 1];
        $this->assertSame([2, 100], $context->sessionSettings()['lottery']);
        $this->assertSame('2026-11-02T12:00:00Z', $context->value('callbacks.event_secret_previous_expires_at'));
    }

    public function test_projection_writer_is_required_even_without_a_native_mapping(): void
    {
        $definition = $this->twoConsumers();
        $definition['consumers']['two']['users']['model'] = null;
        $definition['consumers']['two']['users']['fields'] = [];
        $registry = $this->registry($definition);
        $this->assertSame('one', $registry->identityProjectionWriter('two')->name());
        unset($definition['consumers']['two']['users']['identity_projection_writer']);
        $this->expectException(IdentityException::class);
        $this->registry($definition);
    }

    #[DataProvider('invalidDefinitions')]
    public function test_invalid_definition_is_rejected_without_echoing_input(string $path, mixed $value): void
    {
        $definition = $this->definition();
        $target = &$definition;
        foreach (explode('.', $path) as $segment) {
            $target = &$target[$segment];
        }
        $target = $value;
        $this->expectException(IdentityException::class);
        $this->registry($definition);
    }

    public static function invalidDefinitions(): array
    {
        $cases = [
            'default_consumer' => 'unknown', 'connection' => 'foreign', 'origin' => 'https://legacy.test',
            'consumers' => [], 'consumers.one.connection' => 'foreign', 'consumers.one.origin' => 'https://identity.test/',
            'consumers.one.app_origin' => 'https://consumer.test?query=1', 'consumers.one.application_id' => '',
            'consumers.one.browser.client_secret' => null, 'consumers.one.browser.id_token_algorithm' => 'none',
            'consumers.one.browser.redirect_uri' => 'https://wrong.test/auth/callback',
            'consumers.one.browser.post_logout_redirect_uri' => 'https://consumer.test/elsewhere',
            'consumers.one.resource' => ['client_id' => 'partial'], 'consumers.one.session.secure' => false,
            'consumers.one.session.http_only' => false, 'consumers.one.session.same_site' => 'strict',
            'consumers.one.session.domain' => 'other.test', 'consumers.one.session.path' => '/narrow',
            'consumers.one.session.cookie' => 'invalid name', 'consumers.one.session.lifetime' => 0,
            'consumers.one.session.driver' => 'unregistered', 'consumers.one.session.connection' => 'unknown',
            'consumers.one.routes.event_uri' => 'https://wrong.test/identity/events',
            'consumers.one.routes.path_prefix' => '/a/../b', 'consumers.one.routes.guard' => '',
            'consumers.one.callbacks.event_secret' => 'short', 'consumers.one.callbacks.event_secret_previous' => str_repeat('p', 32),
            'consumers.one.users.model' => ForeignConnectionUser::class, 'consumers.one.users.factory' => 'UnknownFactory',
            'consumers.one.users.mapper' => \stdClass::class, 'consumers.one.users.fields' => ['name' => 'password'],
            'consumers.one.users.identity_projection_writer' => 'missing',
            'consumers.one.sync.import_enabled' => true, 'consumers.one.sync.enabled' => 'yes',
            'consumers.one.local.transaction_seconds' => 301, 'consumers.one.local.idle_seconds' => 50000,
            'consumers.one.delegation.operations' => ['users.profile.update' => ['write' => true, 'resource_type' => 'users']],
            'consumers.one.delegation.routes' => ['documents.show' => 'unregistered'],
            'consumers.one.lock_store' => 'unknown', 'consumers.one.http.ca_bundle' => false,
            'consumers.one.http.max_response_bytes' => -1,
            'consumers.one.session.partitioned' => true,
            'consumers.one.session.lottery' => [101, 100],
            'consumers.one.session.serialization' => 'unregistered',
            'consumers.one.session.block' => true,
            'consumers.one.routes.backchannel_logout_uri' => 'https://consumer.test/auth/sign-in',
            'consumers.one.routes.event_uri' => [],
            'consumers.one.callbacks.event_secret_previous_expires_at' => '2026-02-31T12:00:00Z',

        ];

        return array_map(fn ($path, $value) => [$path, $value], array_keys($cases), array_values($cases));
    }

    #[DataProvider('headlessPrefixes')]
    public function test_headless_custom_callback_and_logout_preserve_exact_configured_urls(string $prefix): void
    {
        $definition = $this->definition();
        $consumer = &$definition['consumers']['one'];
        $consumer = $this->consumer('https://consumer.test', $prefix);
        $consumer['routes']['enabled'] = false;
        $consumer['browser']['redirect_uri'] = 'https://consumer.test'.rtrim($prefix, '/').'/oidc/complete/';
        $consumer['browser']['post_logout_redirect_uri'] = 'https://consumer.test'.rtrim($prefix, '/').'/account/logged-out/';
        $context = $this->registry($definition)->get('one');
        $this->assertSame($consumer['browser']['redirect_uri'], $context->value('browser.redirect_uri'));
        $this->assertSame($consumer['browser']['post_logout_redirect_uri'], $context->value('browser.post_logout_redirect_uri'));
    }

    public static function headlessPrefixes(): array
    {
        return [['/'], ['/workspace']];
    }

    #[DataProvider('headlessWrongOrigins')]
    public function test_headless_custom_endpoints_still_require_the_trusted_origin(string $prefix, string $endpoint): void
    {
        $definition = $this->definition();
        $consumer = &$definition['consumers']['one'];
        $consumer = $this->consumer('https://consumer.test', $prefix);
        $consumer['routes']['enabled'] = false;
        $consumer['browser'][$endpoint] = 'https://foreign.test'.rtrim($prefix, '/').'/oidc/complete';
        $this->expectException(IdentityException::class);
        $this->registry($definition);
    }

    public static function headlessWrongOrigins(): array
    {
        return [['/', 'redirect_uri'], ['/', 'post_logout_redirect_uri'], ['/workspace', 'redirect_uri'], ['/workspace', 'post_logout_redirect_uri']];
    }

    #[DataProvider('headlessEndpoints')]
    public function test_headless_custom_endpoints_cannot_escape_the_trusted_prefix(string $endpoint): void
    {
        $definition = $this->definition();
        $consumer = &$definition['consumers']['one'];
        $consumer = $this->consumer('https://consumer.test', '/workspace');
        $consumer['routes']['enabled'] = false;
        $consumer['browser'][$endpoint] = 'https://consumer.test/elsewhere';
        $this->expectException(IdentityException::class);
        $this->registry($definition);
    }

    public static function headlessEndpoints(): array
    {
        return [['redirect_uri'], ['post_logout_redirect_uri']];
    }

    #[DataProvider('reservedEndpointAliases')]
    public function test_registered_callback_cannot_alias_a_reserved_package_route(string $prefix, string $endpoint): void
    {
        $definition = $this->definition();
        $consumer = &$definition['consumers']['one'];
        $consumer = $this->consumer('https://consumer.test', $prefix);
        $consumer['routes'][$endpoint] = 'https://consumer.test'.rtrim($prefix, '/').'/auth/sign-in/';
        $this->expectException(IdentityException::class);
        $this->registry($definition);
    }

    public static function reservedEndpointAliases(): array
    {
        return [['/', 'event_uri'], ['/', 'backchannel_logout_uri'], ['/workspace', 'event_uri'], ['/workspace', 'backchannel_logout_uri']];
    }

    #[DataProvider('callbackAliasModes')]
    public function test_registered_callbacks_cannot_alias_each_other_after_laravel_slash_normalization(string $prefix, bool $enabled): void
    {
        $definition = $this->definition();
        $consumer = &$definition['consumers']['one'];
        $consumer = $this->consumer('https://consumer.test', $prefix);
        $consumer['routes']['enabled'] = $enabled;
        $consumer['routes']['event_uri'] = 'https://consumer.test'.rtrim($prefix, '/').'/identity/hooks';
        $consumer['routes']['backchannel_logout_uri'] = $consumer['routes']['event_uri'].'/';
        $this->expectException(IdentityException::class);
        $this->registry($definition);
    }

    public static function callbackAliasModes(): array
    {
        return [['/', true], ['/', false], ['/workspace', true], ['/workspace', false]];
    }

    #[DataProvider('headlessBrowserAliases')]
    public function test_headless_custom_browser_endpoint_cannot_alias_another_endpoint(string $prefix, string $section, string $endpoint): void
    {
        $definition = $this->definition();
        $consumer = &$definition['consumers']['one'];
        $consumer = $this->consumer('https://consumer.test', $prefix);
        $consumer['routes']['enabled'] = false;
        $consumer['browser']['redirect_uri'] = 'https://consumer.test'.rtrim($prefix, '/').'/oidc/complete';
        $consumer[$section][$endpoint] = $consumer['browser']['redirect_uri'].'/';
        $this->expectException(IdentityException::class);
        $this->registry($definition);
    }

    public static function headlessBrowserAliases(): array
    {
        return [['/', 'browser', 'post_logout_redirect_uri'], ['/', 'routes', 'event_uri'], ['/workspace', 'browser', 'post_logout_redirect_uri'], ['/workspace', 'routes', 'event_uri']];
    }

    public function test_headless_host_does_not_inherit_disabled_package_route_reservations(): void
    {
        $definition = $this->definition();
        $definition['consumers']['one']['routes']['enabled'] = false;
        $definition['consumers']['one']['routes']['event_uri'] = 'https://consumer.test/auth/sign-in';
        $definition['consumers']['one']['routes']['backchannel_logout_uri'] = 'https://consumer.test/auth/context';
        $context = $this->registry($definition)->get('one');
        $this->assertSame('https://consumer.test/auth/sign-in', $context->value('routes.event_uri'));
        $this->assertSame('https://consumer.test/auth/context', $context->value('routes.backchannel_logout_uri'));
    }

    public function test_noncanonical_callback_path_is_rejected(): void
    {
        $definition = $this->definition();
        $definition['consumers']['one']['routes']['event_uri'] = 'https://consumer.test/<events>';
        $this->expectException(IdentityException::class);
        $this->registry($definition);
    }

    public function test_configuration_failures_do_not_expose_secrets_in_exception_arguments(): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');
        try {
            $definition = $this->definition();
            $definition['consumers']['one']['browser']['client_secret'] = 'sensitive-invalid secret';
            try {
                $this->registry($definition);
                $this->fail('Invalid credential was accepted');
            } catch (IdentityException $error) {
                // The test helper necessarily owns its input; inspect production frames only.
                $frames = array_filter($error->getTrace(), fn (array $frame): bool => str_starts_with($frame['class'] ?? '', 'IdentityPlatform\\Laravel\\Support\\'));
                $this->assertStringNotContainsString('sensitive-invalid', json_encode($frames, JSON_THROW_ON_ERROR));
            }
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }

    public function test_runtime_closures_and_objects_are_refused_even_in_nested_config(): void
    {
        foreach ([fn () => null, new \stdClass] as $runtimeValue) {
            $definition = $this->definition();
            $definition['consumers']['one']['users']['factory'] = $runtimeValue;
            try {
                $this->registry($definition);
                $this->fail('Runtime value was accepted');
            } catch (IdentityException $error) {
                $this->assertSame('invalid_identity_configuration', $error->errorCode);
            }
        }
    }

    public function test_shared_projection_writer_cannot_conflict_or_belong_to_a_foreign_issuer(): void
    {
        foreach (['conflict', 'foreign'] as $case) {
            $definition = $this->twoConsumers();
            if ($case === 'conflict') {
                $definition['consumers']['two']['users']['identity_projection_writer'] = 'two';
            } else {
                $definition['consumers']['one']['origin'] = 'https://foreign.test';
            }
            try {
                $this->registry($definition);
                $this->fail('Invalid common projection writer was accepted');
            } catch (IdentityException $error) {
                $this->assertSame('invalid_identity_projection_writer', $error->errorCode);
            }
        }
    }
}
