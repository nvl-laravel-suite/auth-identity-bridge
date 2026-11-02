<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

require_once __DIR__.'/NamedConfigurationFixture.php';

use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\IdentityServiceProvider;
use IdentityPlatform\Laravel\Services\ServiceTokenManager;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;

class StatelessBootTest extends TestCase
{
    use NamedConfigurationFixture;

    protected function getPackageProviders($app): array
    {
        return [IdentityServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $target = $this->target();
        $target['cache_store'] = 'array';
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('database.default', 'sqlite');
        $app['config']->set('identity', ['default_consumer' => null, 'connection' => null, 'consumers' => [], 'service_targets' => ['reports' => $target]]);
    }

    public function test_service_only_boot_and_token_issuance_have_no_consumer_graph_or_browser_cookie(): void
    {
        Http::fake(['https://worker-issuer.test/*' => Http::response(['access_token' => 'synthetic', 'token_type' => 'Bearer', 'expires_in' => 60, 'scope' => 'reports.read reports.write'])]);
        Route::get('/worker', fn () => response()->json(['issued' => app(ServiceTokenManager::class)->target('reports')->token() === 'synthetic']));
        $this->getJson('https://worker.test/worker')->assertOk()->assertJsonPath('issued', true)->assertCookieMissing('laravel_session');
        $this->assertSame([], app(ConsumerRegistry::class)->names());
    }

    public function test_resource_only_route_requires_explicit_registration_without_starting_a_session(): void
    {
        $resource = $this->consumer();
        $resource['browser'] = $resource['session'] = $resource['routes'] = null;
        $resource['resource'] = ['client_id' => 'independent-resource', 'client_secret' => 'synthetic-resource'];
        $resource['users'] = ['model' => null, 'factory' => null, 'resolver' => null, 'mapper' => null, 'fields' => [], 'identity_projection_writer' => null];
        $resource['delegation'] = ['routes' => [], 'operations' => []];
        $resource['lock_store'] = 'file';
        config(['identity.default_consumer' => 'api', 'identity.consumers' => ['api' => $resource]]);
        $this->app->forgetInstance(ConsumerRegistry::class);
        $this->app->forgetInstance(Identity::class);
        Route::get('/resource', fn () => response()->json(['resource' => app(IdentityConfig::class)->credentials('resource')['id'], 'session' => request()->hasSession()]))->defaults('identity_consumer', 'api')->defaults('identity_stateless', true);
        $response = $this->getJson('https://consumer.test/resource');
        $response->assertOk()->assertJsonPath('resource', 'independent-resource')->assertJsonPath('session', false);
        $this->assertSame([], $response->headers->getCookies());
        $this->getJson('https://wrong.test/resource')->assertStatus(404);
    }
}
