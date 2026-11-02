<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Auth;

use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;

class HeadlessEntryPortsTest extends TestCase
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
    public function test_entry_form_uses_the_exact_selected_consumer_authority_with_compiled_routes(bool $cached): void
    {
        if ($cached) {
            $router = app('router');
            $router->setCompiledRoutes($router->getRoutes()->compile());
        }
        foreach (['https://consumer.test', 'https://consumer.test:8443'] as $origin) {
            $this->get($origin.'/auth/entry')->assertOk()->assertSee('action="'.$origin.'/auth/sign-in"', false)->assertSee('name="_token"', false);
        }
        self::assertTrue(Route::has('identity.one.entry'));
        self::assertTrue(Route::has('identity.two.entry'));
        $this->get('https://consumer.test:9443/auth/entry')->assertNotFound();
    }
}
