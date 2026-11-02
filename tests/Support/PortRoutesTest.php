<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;

class PortRoutesTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $two = $app['config']->get('identity.consumers.one');
        $two['app_origin'] = 'https://consumer.test:8443';
        $two['browser']['client_id'] = 'web-2';
        $two['browser']['redirect_uri'] = $two['app_origin'].'/auth/callback';
        $two['browser']['post_logout_redirect_uri'] = $two['app_origin'].'/signed-out';
        $two['routes']['event_uri'] = $two['app_origin'].'/identity/events';
        $two['routes']['backchannel_logout_uri'] = $two['app_origin'].'/auth/backchannel-logout';
        $two['routes']['guard'] = 'identity_two';
        $two['session']['cookie'] = '__Host-two';
        $two['callbacks']['event_secret'] = str_repeat('b', 32);
        $app['config']->set('identity.consumers.two', $two);
    }

    public static function routeForms(): array
    {
        return [[false], [true]];
    }

    #[DataProvider('routeForms')]
    public function test_package_routes_remain_distinct_on_the_same_hostname_and_path_with_different_ports(bool $cached): void
    {
        if ($cached) {
            $router = app('router');
            $router->setCompiledRoutes($router->getRoutes()->compile());
        }
        $body = json_encode(['schema_version' => 1, 'event_id' => 'port-event', 'type' => 'service.updated', 'application_id' => 'app-1', 'occurred_at' => '2026-10-28T12:00:00Z', 'subject' => null], JSON_THROW_ON_ERROR);
        $timestamp = (string) time();
        foreach (['https://consumer.test' => 'e', 'https://consumer.test:8443' => 'b'] as $origin => $secret) {
            $this->call('POST', $origin.'/identity/events', [], [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_X_IDENTITY_EVENT_ID' => 'port-event', 'HTTP_X_IDENTITY_TIMESTAMP' => $timestamp, 'HTTP_X_IDENTITY_SIGNATURE' => 'v1='.hash_hmac('sha256', 'port-event.'.$timestamp.'.'.$body, str_repeat($secret, 32))], $body)->assertOk()->assertJsonPath('duplicate', false);
        }
        $this->assertTrue(Route::has('identity.one.events'));
        $this->assertTrue(Route::has('identity.two.events'));
        $this->assertSame('/identity/events', route('identity.one.events', absolute: false));
        $this->assertSame('/identity/events', route('identity.two.events', absolute: false));
        $this->postJson('https://consumer.test:9443/identity/events')->assertNotFound();
    }
}
