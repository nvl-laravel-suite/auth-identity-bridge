<?php

namespace IdentityPlatform\Laravel\Tests;

require_once __DIR__.'/Support/NamedConfigurationFixture.php';

use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\IdentityServiceProvider;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\ConsumerSessionManager;
use IdentityPlatform\Laravel\Support\ServiceTargetRegistry;
use IdentityPlatform\Laravel\Tests\Support\FixtureNativeFactory;
use IdentityPlatform\Laravel\Tests\Support\NamedConfigurationFixture;
use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    use NamedConfigurationFixture;

    protected function getPackageProviders($app): array
    {
        return [IdentityServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('database.default', 'sqlite');
        $app['config']->set('database.connections.sqlite', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true]);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('cache.stores.identity_tests', ['driver' => 'file', 'path' => sys_get_temp_dir().'/identity-package-'.getmypid().'/'.hash('sha256', $this->nameWithDataSet())]);
        $app['config']->set('session.driver', 'array');
        $definition = $this->definition();
        $definition['consumers']['one']['users']['model'] = null;
        $definition['consumers']['one']['users']['fields'] = [];
        $definition['consumers']['one']['browser']['client_secret'] = 'secret';
        $definition['consumers']['one']['resource'] = ['client_id' => 'verifier-1', 'client_secret' => 'resource-secret'];
        $definition['consumers']['one']['session']['driver'] = 'file';
        $definition['consumers']['one']['session']['files'] = sys_get_temp_dir().'/identity-sessions-'.getmypid().'/'.hash('sha256', $this->nameWithDataSet());
        $app['files']->ensureDirectoryExists($definition['consumers']['one']['session']['files']);
        $definition['consumers']['one']['session']['connection'] = null;
        $definition['consumers']['one']['session']['cookie'] = $app['config']->get('session.cookie', 'identity_session');
        $definition['consumers']['one']['session']['encrypt'] = false;
        $definition['consumers']['one']['lock_store'] = 'identity_tests';
        $definition['consumers']['one']['delegation'] = ['routes' => [], 'operations' => []];
        $definition['service_targets']['reports'] = ['origin' => 'https://identity.test', 'application_id' => 'app-1', 'base_url' => 'https://consumer.test/api', 'client_id' => 'worker-1', 'client_secret' => 'service-secret', 'scopes' => ['documents.read'], 'cache_store' => 'array', 'http' => ['ca_bundle' => null, 'max_response_bytes' => 131072]];
        $app['config']->set('identity', $definition);
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->selectConsumer();
        config(['session' => $this->graph()->context->sessionSettings()]);
        $this->app->instance('session', new ConsumerSessionManager($this->app, $this->graph()->context, true));
    }

    public function withSession(array $data)
    {
        parent::withSession($data);
        $store = $this->app['session']->driver();
        $store->save();

        return $this->withCookie($store->getName(), $store->getId());
    }

    protected function selectConsumer(string $name = 'one'): void
    {
        $this->app->forgetInstance(ConsumerRegistry::class);
        $this->app->forgetInstance(Identity::class);
        $this->app->forgetInstance(ServiceTargetRegistry::class);
        $this->app->instance(ConsumerGraph::class, $this->app->make(Identity::class)->consumer($name, $this->app['request']));
    }

    protected function configure(array $values): void
    {
        config($values);
        if (array_any(array_keys($values), fn ($key) => str_starts_with($key, 'identity.') || str_starts_with($key, 'database.'))) {
            $this->selectConsumer();
        }
    }

    protected function bindRequest(Request $request): void
    {
        $this->app->instance('request', $request);
        $graph = $this->graph();
        $graph->instance(Request::class, $request);
        if ($graph->resolved(IdentityAccess::class)) {
            $graph->make(IdentityAccess::class)->setRequest($request);
        }
    }

    protected function nativeFactory(\Closure $factory): void
    {
        FixtureNativeFactory::$create = $factory;
        $this->configure(['identity.consumers.one.users.factory' => FixtureNativeFactory::class]);
    }

    protected function graph(): ConsumerGraph
    {
        return $this->app->make(ConsumerGraph::class);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }
}
