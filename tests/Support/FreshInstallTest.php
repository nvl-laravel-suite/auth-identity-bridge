<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

require_once __DIR__.'/NamedConfigurationFixture.php';

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\IdentityServiceProvider;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use Illuminate\Filesystem\Filesystem;
use Orchestra\Testbench\TestCase;

class FreshInstallTest extends TestCase
{
    use NamedConfigurationFixture;

    private array $originalArguments;

    private string $fixtureDirectory;

    protected function setUp(): void
    {
        $this->originalArguments = $_SERVER['argv'];
        $_SERVER['argv'] = ['artisan', 'package:discover'];
        $this->fixtureDirectory = sys_get_temp_dir().'/identity-fresh-'.bin2hex(random_bytes(8));
        mkdir($this->fixtureDirectory.'/bootstrap/cache', 0700, true);
        mkdir($this->fixtureDirectory.'/config', 0700, true);
        parent::setUp();
    }

    protected function tearDown(): void
    {
        $_SERVER['argv'] = $this->originalArguments;
        (new Filesystem)->deleteDirectory($this->fixtureDirectory);
        parent::tearDown();
    }

    protected function getPackageProviders($app): array
    {
        return [IdentityServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app->useBootstrapPath($this->fixtureDirectory.'/bootstrap');
        $app->useConfigPath($this->fixtureDirectory.'/config');
        $app['config']->set('identity.consumers.default.origin', null);
        $app['config']->set('identity.consumers.default.browser.client_id', null);
        $app['config']->set('identity.consumers.default.browser.client_secret', null);
        $app['config']->set('database.default', 'native');
        $app['config']->set('database.connections.native', ['driver' => 'sqlite', 'database' => ':memory:']);
        $app['config']->set('database.connections.sessions', ['driver' => 'sqlite', 'database' => ':memory:']);
        $app['config']->set('cache.stores.shared', ['driver' => 'file', 'path' => $this->fixtureDirectory.'/locks']);
    }

    public function test_fresh_discovery_and_publication_work_but_runtime_graphs_require_complete_configuration(): void
    {
        $this->artisan('package:discover')->assertExitCode(0);
        $this->artisan('vendor:publish', ['--tag' => 'identity-config', '--force' => true])->assertExitCode(0);
        $this->assertFileExists($this->fixtureDirectory.'/config/identity.php');
        $this->assertSame([], $this->app['router']->getRoutes()->getRoutesByName());
        try {
            app(Identity::class)->consumer('default');
            $this->fail('Fresh unconfigured host created a runtime graph');
        } catch (IdentityException $error) {
            $this->assertSame('invalid_identity_configuration', $error->errorCode);
        }
        $_SERVER['argv'] = ['artisan', 'queue:work'];
        try {
            (new IdentityServiceProvider($this->app))->boot();
            $this->fail('Unconfigured runtime boot was allowed');
        } catch (IdentityException $error) {
            $this->assertSame('invalid_identity_configuration', $error->errorCode);
        }
        config(['identity' => $this->definition()]);
        $this->app->forgetInstance(ConsumerRegistry::class);
        $this->app->forgetInstance(Identity::class);
        (new IdentityServiceProvider($this->app))->boot();
        $this->assertSame('web-1', app(Identity::class)->consumer('one')->context->clientId());
        $this->app['router']->getRoutes()->refreshNameLookups();
        $this->assertTrue($this->app['router']->has('identity.one.callback'));
    }
}
