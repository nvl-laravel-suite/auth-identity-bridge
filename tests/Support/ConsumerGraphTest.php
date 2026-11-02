<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

require_once __DIR__.'/NamedConfigurationFixture.php';

use IdentityPlatform\Laravel\Callbacks\CallbackRepository;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\Repositories\LoginRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserSnapshotClient;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;

class ConsumerGraphTest extends TestCase
{
    use NamedConfigurationFixture;

    public function test_retained_graphs_and_vaults_never_follow_another_selection_or_mutable_config(): void
    {
        $this->assertTrue(class_exists(Identity::class), 'Explicit immutable consumer graph is missing');
        $identity = new Identity($this->app, $this->registry($this->twoConsumers()));
        $one = $identity->consumer('one');
        $two = $identity->consumer('two');
        $vault = $one->make(IdentityVault::class);
        $sealed = $vault->seal(['value' => 'one'], 'fixture');
        $this->configure(['identity.consumers.one.browser.client_id' => 'mutated']);
        $this->assertSame('web-1', $one->make(IdentityConfig::class)->clientId());
        $this->assertSame('web-2', $two->make(IdentityConfig::class)->clientId());
        try {
            $two->make(IdentityVault::class)->open($sealed, 'fixture');
            $this->fail('Another binding opened the vault');
        } catch (IdentityException $error) {
            $this->assertSame('vault_binding_failed', $error->errorCode);
        }
        $this->assertSame(['value' => 'one'], $vault->open($sealed, 'fixture'));
    }

    public function test_swapped_login_state_is_not_consumed_by_another_graph(): void
    {
        $this->assertTrue(class_exists(Identity::class), 'Explicit immutable consumer graph is missing');
        $identity = new Identity($this->app, $this->registry($this->twoConsumers()));
        $one = $identity->consumer('one')->make(LoginRepository::class);
        $two = $identity->consumer('two')->make(LoginRepository::class);
        $state = $one->create('browser', ['nonce' => 'one'], 'oidc');
        try {
            $two->consume($state, 'browser', 'oidc');
            $this->fail('Another binding consumed login state');
        } catch (IdentityException $error) {
            $this->assertSame('invalid_login_state', $error->errorCode);
        }
        $this->assertSame('one', $one->consume($state, 'browser', 'oidc')['nonce']);
    }

    public function test_callback_late_sync_resolution_keeps_the_receiving_graph(): void
    {
        Queue::fake();
        $definition = $this->twoConsumers();
        $definition['consumers']['two']['sync']['enabled'] = true;
        $identity = new Identity($this->app, $this->registry($definition));
        $two = $identity->consumer('two');
        $two->make(CallbackRepository::class)->event(['event_id' => 'same-id', 'type' => 'profile.invalidated', 'subject' => 'person'], 'digest');
        $this->assertDatabaseHas('identity_user_sync_requests', ['binding_hash' => $two->context->bindingHash(), 'subject' => 'person']);
        $this->assertDatabaseMissing('identity_user_sync_requests', ['binding_hash' => $identity->consumer('one')->context->bindingHash()]);
    }

    public function test_explicit_other_graph_does_not_escape_outer_browser_delegation(): void
    {
        $request = Request::create('https://consumer.test/');
        $store = new Store('fixture', new ArraySessionHandler(120));
        $store->start();
        $store->put('identity.session', 'delegated-fixture');
        $request->setLaravelSession($store);
        $this->bindRequest($request);
        app(OverlayRepository::class)->save('delegated-fixture', ['status' => 'pending', 'browser_binding' => str_repeat('b', 43), 'context_version' => 1, 'source_sid' => 'source', 'expires_at' => now()->addMinute()]);
        $definition = $this->twoConsumers();
        $definition['consumers']['two']['sync']['enabled'] = true;
        $other = (new Identity($this->app, $this->registry($definition)))->consumer('two');
        Http::fake();
        try {
            $other->make(UserSnapshotClient::class)->read(['person']);
            $this->fail('A new graph escaped the outer delegated browser');
        } catch (IdentityException $error) {
            $this->assertSame('delegation_outbound_forbidden', $error->errorCode);
        }
        Http::assertNothingSent();
    }
}
