<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Auth;

use IdentityPlatform\Laravel\Auth\BrowserDestination;
use IdentityPlatform\Laravel\Auth\BrowserLifecycle;
use IdentityPlatform\Laravel\Auth\PostContextDestinationResolver;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Facades\Identity;
use IdentityPlatform\Laravel\Support\ConsumerContext;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Tests\TestCase;

class TrustedSurfaceResolver implements PostContextDestinationResolver
{
    public function __construct(private ConsumerRegistry $registry) {}

    public function resolve(ConsumerContext $consumer, string $returnPath): BrowserDestination
    {
        return BrowserDestination::surface($this->registry, 'two');
    }
}

class HeadlessRoutesTest extends TestCase
{
    public function test_entry_renders_target_owned_csrf_form_and_is_part_of_registered_routes(): void
    {
        self::assertTrue(class_exists(BrowserLifecycle::class), 'Public headless lifecycle is missing');
        $response = $this->get('https://consumer.test/auth/entry?return_to=https://foreign.test');
        $response->assertOk()->assertSee('https://consumer.test/auth/sign-in', false)->assertSee('name="_token"', false);
        $response->assertDontSee('foreign.test');
        self::assertSame('identity.one.entry', app(IdentityConfig::class)->routeName('entry'));
        self::assertSame('https://consumer.test/auth/entry', app(IdentityConfig::class)->url('entry'));
        self::assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
    }

    public function test_entry_collision_is_rejected_by_the_existing_configuration_owner(): void
    {
        $this->expectException(IdentityException::class);
        $this->configure(['identity.consumers.one.routes.event_uri' => 'https://consumer.test/auth/entry']);
        $this->graph();
    }

    public function test_trusted_surface_resolver_survives_graph_binding_and_transfers_no_credentials_or_return_path(): void
    {
        self::assertTrue(class_exists(BrowserLifecycle::class), 'Public headless lifecycle is missing');
        $definition = config('identity');
        $definition['consumers']['two'] = $definition['consumers']['one'];
        $definition['consumers']['two']['app_origin'] = 'https://second.test:8443';
        $definition['consumers']['two']['browser']['redirect_uri'] = 'https://second.test:8443/auth/callback';
        $definition['consumers']['two']['browser']['post_logout_redirect_uri'] = 'https://second.test:8443/signed-out';
        $definition['consumers']['two']['routes']['event_uri'] = 'https://second.test:8443/identity/events';
        $definition['consumers']['two']['routes']['backchannel_logout_uri'] = 'https://second.test:8443/identity/backchannel-logout';
        $definition['consumers']['two']['routes']['guard'] = 'identity_two';
        $definition['consumers']['two']['session']['cookie'] = '__Host-two';
        $this->app->bind(PostContextDestinationResolver::class, TrustedSurfaceResolver::class);
        $this->configure(['identity' => $definition]);
        $this->selectConsumer();
        $resolver = $this->graph()->make(PostContextDestinationResolver::class);
        $destination = $resolver->resolve($this->graph()->context, '/documents?private=source-only');
        self::assertSame(['kind' => 'surface', 'url' => 'https://second.test:8443/auth/entry', 'consumer' => 'two'], $destination->jsonSerialize());
        self::assertNotSame($this->graph()->context->sessionSettings()['cookie'], app(ConsumerRegistry::class)->get('two')->sessionSettings()['cookie']);
        foreach (['https://evil.test', '//evil.test', '/%2f%2fevil.test', '/a/../private'] as $unsafe) {
            self::assertSame('/', BrowserDestination::local($unsafe)->url);
        }
        $this->expectException(IdentityException::class);
        BrowserDestination::surface(app(ConsumerRegistry::class), 'unknown');
    }

    public function test_facade_requires_selected_request_graph_and_never_borrows_default_in_background(): void
    {
        self::assertTrue(class_exists(BrowserLifecycle::class), 'Public headless lifecycle is missing');
        $this->app->forgetInstance(ConsumerGraph::class);
        $this->expectException(IdentityException::class);
        Identity::browser();
    }

    public function test_browser_and_json_command_errors_are_sanitized_and_do_not_create_sessions(): void
    {
        $this->postJson('https://consumer.test/auth/sign-in', [], ['Origin' => 'https://foreign.test'])->assertForbidden()->assertExactJson(['error' => 'origin_refused']);
        $this->post('https://consumer.test/auth/sign-in', [], ['Origin' => 'https://foreign.test'])->assertForbidden()->assertExactJson(['error' => 'origin_refused']);
        $this->assertDatabaseCount('identity_sessions', 0);
    }
}
