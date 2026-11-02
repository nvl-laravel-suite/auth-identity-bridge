<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

require_once __DIR__.'/AppAdapterFixture.php';

use ConsumerHostFixtures\AppMapper;
use ConsumerHostFixtures\BoundHelper;
use ConsumerHostFixtures\HelperContract;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Tests\TestCase;
use IdentityPlatform\Laravel\Users\NativeUserMapper;
use Illuminate\Contracts\Cache\Factory;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Http;

class TransitiveAdapterTest extends TestCase
{
    use NamedConfigurationFixture;

    public function test_application_helpers_retain_graph_local_config_repositories_and_transport_in_a_b_a_and_background(): void
    {
        $definition = $this->twoConsumers();
        foreach ($definition['consumers'] as &$consumer) {
            $consumer['users']['mapper'] = AppMapper::class;
        }
        unset($consumer);
        $this->app->singleton(HelperContract::class, BoundHelper::class);
        $ambientHelper = $this->app->make(HelperContract::class);
        $identity = new Identity($this->app, $this->registry($definition));
        $one = $identity->consumer('one');
        $two = $identity->consumer('two');
        Http::fake(['https://identity.test/*' => Http::response(['ok' => true])]);
        $first = $one->make(NativeUserMapper::class);
        $second = $two->make(NativeUserMapper::class);
        $this->assertNotSame($ambientHelper, $second->bound);
        $this->app->instance(ConsumerGraph::class, $two);
        $this->assertSame('web-1', $one->make(NativeUserMapper::class)->helper->config->clientId());
        foreach ([[$one, $first, 'web-1'], [$two, $second, 'web-2'], [$one, $first, 'web-1']] as [$graph, $mapper, $client]) {
            $this->assertSame($client, $mapper->helper->config->clientId());
            $this->assertSame($client, $mapper->bound->helper->config->clientId());
            $this->assertSame($graph->make(IdentityConfig::class), $mapper->helper->container->make(IdentityConfig::class));
            $this->assertSame($this->app->make(Factory::class), $mapper->helper->cache);
            $this->assertSame($this->app->make(Dispatcher::class), $mapper->helper->events);
            $this->assertSame($this->app['db'], $mapper->helper->database);
            $state = $mapper->helper->logins->create('browser', ['client' => $client], 'oidc');
            $this->assertDatabaseHas('identity_logins', ['id' => hash('sha256', $state), 'binding_hash' => $graph->context->bindingHash()]);
            $mapper->helper->http->form('/api/auth/oauth2/token', []);
            Http::assertSent(fn ($request) => $request->hasHeader('Authorization', 'Basic '.base64_encode($client.':'.$graph->context->credentials('browser')['secret'])));
        }
        $this->app->forgetInstance(ConsumerGraph::class);
        $background = $identity->consumer('two')->make(NativeUserMapper::class);
        $this->assertSame('web-2', $background->helper->config->clientId());
        $this->assertSame('web-2', $background->bound->helper->config->clientId());
    }
}
