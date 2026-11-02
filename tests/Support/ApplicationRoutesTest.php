<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

use IdentityPlatform\Laravel\Facades\Identity;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Bootstrap\LoadConfiguration;
use Illuminate\Support\Facades\Route;

class ApplicationRoutesTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('identity.consumers.one.routes.enabled', false);
        $app['config']->set('identity.consumers.one.routes.path_prefix', '/workspace');
        $app['config']->set('identity.consumers.one.browser.redirect_uri', 'https://consumer.test/workspace/custom-return');
        $app['config']->set('identity.consumers.one.browser.post_logout_redirect_uri', 'https://consumer.test/workspace/bye');
        $app['config']->set('identity.consumers.one.routes.event_uri', 'https://consumer.test/workspace/events');
        $app['config']->set('identity.consumers.one.routes.backchannel_logout_uri', 'https://consumer.test/workspace/backchannel');
        $snapshot = var_export($app['config']->get('identity'), true);
        $cached = eval('return '.$snapshot.';');
        $app['config']->set('identity', $cached);
    }

    public function test_cached_scalar_definition_supports_explicit_application_owned_callbacks(): void
    {
        $this->assertFalse(Route::has('identity.one.callback'));
        Route::middleware('web')->get('/workspace/custom-return', fn (IdentityConfig $config) => response()->json(['client' => $config->clientId(), 'return' => $config->url('callback'), 'logout' => $config->url('signed-out'), 'contexts' => $config->url('contexts')]))->defaults('identity_consumer', 'one');
        $this->getJson('https://consumer.test/workspace/custom-return')->assertOk()->assertExactJson(['client' => 'web-1', 'return' => 'https://consumer.test/workspace/custom-return', 'logout' => 'https://consumer.test/workspace/bye', 'contexts' => 'https://consumer.test/workspace/auth/contexts']);
        $this->getJson('https://wrong.test/workspace/custom-return')->assertStatus(404);
    }

    public function test_laravel_loads_the_named_definition_from_an_actual_config_cache_file(): void
    {
        $cache = tempnam(sys_get_temp_dir(), 'identity-config-cache-');
        $original = Container::getInstance();
        $definition = config('identity');
        try {
            file_put_contents($cache, '<?php return '.var_export(['app' => ['env' => 'testing'], 'identity' => $definition, 'p1bc_cache_probe' => 'loaded'], true).';');
            $cachedApp = new class($cache) extends Application
            {
                public function __construct(private string $fixtureCache)
                {
                    parent::__construct(sys_get_temp_dir());
                }

                public function getCachedConfigPath(): string
                {
                    return $this->fixtureCache;
                }
            };
            (new LoadConfiguration)->bootstrap($cachedApp);
            $this->assertTrue($cachedApp['config_loaded_from_cache']);
            $this->assertSame('loaded', $cachedApp['config']->get('p1bc_cache_probe'));
            $loaded = $cachedApp['config']->get('identity');
        } finally {
            Container::setInstance($original);
            unlink($cache);
        }
        $this->configure(['identity' => $loaded]);
        $graph = Identity::consumer('one');
        $this->assertSame('web-1', $graph->make(IdentityConfig::class)->clientId());
        $this->assertSame('https://consumer.test/workspace/custom-return', $graph->make(IdentityConfig::class)->url('callback'));
    }
}
