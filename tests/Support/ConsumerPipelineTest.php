<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Http\Middleware\SelectConsumer;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\ContainerInstances;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;

class BoundController
{
    public function __construct(private IdentityConfig $config) {}

    public function __invoke()
    {
        return response()->json(['client' => $this->config->clientId(), 'cookie' => config('session.cookie')]);
    }
}

class ConsumerPipelineTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $second = $app['config']->get('identity.consumers.one');
        $second['app_origin'] = 'https://second.test';
        $second['browser']['client_id'] = 'web-2';
        $second['browser']['redirect_uri'] = 'https://second.test/auth/callback';
        $second['browser']['post_logout_redirect_uri'] = 'https://second.test/signed-out';
        $second['routes']['event_uri'] = 'https://second.test/identity/events';
        $second['routes']['backchannel_logout_uri'] = 'https://second.test/auth/backchannel-logout';
        $second['routes']['guard'] = 'identity_two';
        $second['callbacks']['event_secret'] = str_repeat('b', 32);
        $app['config']->set('identity.consumers.two', $second);
    }

    public function test_same_route_controller_is_reconstructed_for_sequential_a_b_a(): void
    {
        Route::middleware('web')->get('/bound-controller', BoundController::class);
        foreach (['consumer.test' => 'web-1', 'second.test' => 'web-2', 'consumer.test:443' => 'web-1'] as $host => $client) {
            $this->getJson('https://'.$host.'/bound-controller')->assertOk()->assertJsonPath('client', $client);
        }
    }

    public function test_selection_precedes_controller_di_and_restores_framework_settings(): void
    {
        $this->assertTrue(class_exists(SelectConsumer::class), 'Early trusted selection is missing');
        Route::middleware('web')->get('/bound-controller', BoundController::class);
        $before = config('session');
        $this->getJson('https://consumer.test/bound-controller?consumer=untrusted')->assertOk()->assertJsonPath('client', 'web-1');
        $this->assertSame($before, config('session'));
        $this->getJson('https://wrong.test/bound-controller')->assertStatus(404);
    }

    public function test_encoded_unicode_resource_tail_keeps_the_trusted_consumer(): void
    {
        Route::middleware('web')->get('/bound-controller/{record}', BoundController::class);
        $this->getJson('https://consumer.test/bound-controller/%E2%82%AC')->assertOk()->assertJsonPath('client', 'web-1');
        $this->getJson('https://consumer.test/bound-controller/a%20file')->assertOk()->assertJsonPath('client', 'web-1');
    }

    public function test_same_name_encrypted_cookie_swap_cannot_touch_the_original_framework_session(): void
    {
        $this->withCredentials();
        Route::middleware('web')->get('/session-probe', function (Request $request) {
            $client = app(IdentityConfig::class)->clientId();
            if ($request->boolean('create')) {
                $request->session()->put('owner', $client);
            }
            if ($request->session()->get('owner') !== $client) {
                throw new IdentityException('sign_in_required', 401);
            }

            return response()->json(['owner' => $request->session()->get('owner')]);
        });
        $created = $this->getJson('https://consumer.test/session-probe?create=1')->assertOk();
        $cookieName = $this->graph()->context->sessionSettings()['cookie'];
        $cookie = array_values(array_filter($created->headers->getCookies(), fn ($cookie) => $cookie->getName() === $cookieName))[0];
        $this->withUnencryptedCookie($cookieName, $cookie->getValue());
        $this->getJson('https://second.test/session-probe')->assertStatus(401);
        $this->getJson('https://consumer.test/session-probe')->assertOk()->assertJsonPath('owner', 'web-1');
    }

    public function test_inner_exception_restores_existing_stores_guards_facades_and_config(): void
    {
        $session = app('session');
        $auth = Auth::getFacadeRoot();
        $cookie = app('cookie');
        $settings = config('session');
        $authentication = config('auth');
        $graph = $this->graph();
        Route::middleware('web')->get('/explode', function () {
            session()->put('uncommitted', true);
            throw new \RuntimeException('synthetic-inner-failure');
        });
        $this->withoutExceptionHandling();
        try {
            $this->get('https://second.test/explode');
            $this->fail('Expected inner failure');
        } catch (\RuntimeException $error) {
            $this->assertSame('synthetic-inner-failure', $error->getMessage());
        }
        $this->assertSame($settings, config('session'));
        $this->assertSame($authentication, config('auth'));
        $this->assertSame($session, app('session'));
        $this->assertSame($auth, Auth::getFacadeRoot());
        $this->assertSame($cookie, app('cookie'));
        $this->assertSame($graph, $this->graph());
    }

    public static function redirectEntryPoints(): array
    {
        $cases = [];
        foreach (['validation', 'redirect_facade', 'response_helper', 'response_facade'] as $entry) {
            foreach ([false, true] as $resolved) {
                foreach (['second.test', 'consumer.test'] as $otherHost) {
                    $cases[$entry.($resolved ? '_already_resolved_' : '_first_resolution_in_scope_').$otherHost] = [$entry, $resolved, $otherHost];
                }
            }
        }

        return $cases;
    }

    #[DataProvider('redirectEntryPoints')]
    public function test_redirects_keep_validation_and_private_old_input_in_the_current_a_b_a_session(string $entry, bool $resolved, string $otherHost): void
    {
        if ($resolved) {
            Redirect::getFacadeRoot();
            Response::getFacadeRoot();
        } else {
            $this->assertFalse(app()->resolved('redirect'));
            $this->assertFalse(app()->resolved(ResponseFactory::class));
        }
        Route::middleware('web')->post('/draft', function (Request $request) use ($entry) {
            if ($entry === 'validation') {
                $request->validate(['reason' => ['required']]);
            }

            return match ($entry) {
                'redirect_facade' => Redirect::to('/draft')->withInput(),
                'response_helper' => response()->redirectTo('/draft')->withInput(),
                'response_facade' => Response::redirectTo('/draft')->withInput(),
            };
        });
        Route::middleware('web')->get('/draft', function () {
            return new JsonResponse([
                'reason_error' => view()->shared('errors')->has('reason'),
                'draft' => old('draft'),
            ]);
        });
        $cookies = [];
        $cookieName = $this->graph()->context->sessionSettings()['cookie'];
        $select = function (string $browser) use (&$cookies, $cookieName): void {
            $this->defaultCookies = [];
            $this->unencryptedCookies = [];
            if (isset($cookies[$browser])) {
                $this->withUnencryptedCookie($cookieName, $cookies[$browser]);
            }
        };
        $hosts = ['a' => 'consumer.test', 'b' => $otherHost];
        foreach ([['a', 'private-a-first'], ['b', 'private-b'], ['a', 'private-a-last']] as [$browser, $draft]) {
            $host = $hosts[$browser];
            $select($browser);
            $response = $this->from('https://'.$host.'/draft')->post('https://'.$host.'/draft', ['reason' => '', 'draft' => $draft]);
            $response->assertRedirect('https://'.$host.'/draft');
            $cookies[$browser] = $response->getCookie($cookieName, false)->getValue();
            $select($browser);
            $this->get('https://'.$host.'/draft')->assertOk()->assertExactJson([
                'reason_error' => $entry === 'validation',
                'draft' => $draft,
            ]);
            $other = $browser === 'a' ? 'b' : 'a';
            $select($other);
            $this->get('https://'.$hosts[$other].'/draft')->assertOk()->assertExactJson(['reason_error' => false, 'draft' => null]);
        }
    }

    public static function redirectRestorationCases(): array
    {
        return [
            'resolved_normal' => [true, false],
            'resolved_exception' => [true, true],
            'unresolved_normal' => [false, false],
            'unresolved_exception' => [false, true],
        ];
    }

    #[DataProvider('redirectRestorationCases')]
    public function test_redirect_dependencies_restore_after_normal_and_exception_paths(bool $resolved, bool $throws): void
    {
        $session = app('session.store');
        $session->put('host_private', 'host-only');
        $redirect = $resolved ? Redirect::getFacadeRoot() : null;
        $response = $resolved ? Response::getFacadeRoot() : null;
        $seen = [];
        Route::middleware('web')->get('/redirect-scope', function (Request $request) use (&$seen, $throws) {
            $seen = [Redirect::getFacadeRoot(), Response::getFacadeRoot(), $request->session()];
            Redirect::to('/draft')->with('scoped_private', 'consumer-only');
            Response::redirectTo('/draft')->with('response_private', 'consumer-only');
            if ($throws) {
                throw new \RuntimeException('synthetic-redirect-failure');
            }

            return new JsonResponse(['ok' => true]);
        });
        $this->withoutExceptionHandling();
        try {
            $this->get('https://second.test/redirect-scope')->assertOk();
            $this->assertFalse($throws, 'Expected synthetic exception');
        } catch (\RuntimeException $error) {
            $this->assertTrue($throws);
            $this->assertSame('synthetic-redirect-failure', $error->getMessage());
        }
        $this->assertSame($session, app('session.store'));
        $this->assertSame('host-only', $session->get('host_private'));
        $this->assertNull($session->get('scoped_private'));
        $this->assertNull($session->get('response_private'));
        $this->assertNotSame($session, $seen[2]);
        $this->assertSame('consumer-only', $seen[2]->get('scoped_private'));
        $this->assertSame('consumer-only', $seen[2]->get('response_private'));
        if ($resolved) {
            $this->assertSame($redirect, redirect());
            $this->assertSame($redirect, Redirect::getFacadeRoot());
            $this->assertSame($response, response());
            $this->assertSame($response, Response::getFacadeRoot());
            $this->assertNotSame($redirect, $seen[0]);
            $this->assertNotSame($response, $seen[1]);
        } else {
            $this->assertArrayNotHasKey('redirect', ContainerInstances::all(app()));
            $this->assertArrayNotHasKey(ResponseFactory::class, ContainerInstances::all(app()));
            $this->assertNotSame($seen[0], Redirect::getFacadeRoot());
            $this->assertNotSame($seen[1], Response::getFacadeRoot());
        }
    }

    public function test_route_metadata_cannot_override_trusted_host_and_duplicate_cookies_refuse_early(): void
    {
        Route::middleware('web')->get('/wrong-registration', BoundController::class)->defaults('identity_consumer', 'two');
        $this->getJson('https://consumer.test/wrong-registration')->assertStatus(404);
        Route::middleware('web')->get('/duplicate', BoundController::class);
        $name = $this->graph()->context->sessionSettings()['cookie'];
        $this->withServerVariables(['HTTP_COOKIE' => $name.'=first; '.$name.'=second'])->getJson('https://consumer.test/duplicate')->assertStatus(400);
    }

    public function test_signed_callback_cannot_cross_bindings_and_same_message_id_stays_independent(): void
    {
        $identity = app(Identity::class);
        foreach (['one', 'two'] as $name) {
            IdentitySession::create(['id' => $name, 'binding_hash' => $identity->consumer($name)->context->bindingHash(), 'user_id' => null, 'subject' => 'person', 'sid' => 'source', 'token_vault' => 'fixture', 'selection' => [], 'context_version' => 1, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        }
        $body = json_encode(['schema_version' => 1, 'event_id' => 'same-id', 'type' => 'catalog.published', 'application_id' => 'app-1', 'occurred_at' => gmdate('Y-m-d\TH:i:s\Z'), 'subject' => null]);
        $timestamp = (string) time();
        $headers = ['CONTENT_TYPE' => 'application/json', 'HTTP_X_IDENTITY_EVENT_ID' => 'same-id', 'HTTP_X_IDENTITY_TIMESTAMP' => $timestamp, 'HTTP_X_IDENTITY_SIGNATURE' => 'v1='.hash_hmac('sha256', 'same-id.'.$timestamp.'.'.$body, str_repeat('e', 32))];
        $this->call('POST', 'https://second.test/identity/events', [], [], [], $headers, $body)->assertStatus(401);
        $response = $this->call('POST', 'https://consumer.test/identity/events', [], [], [], $headers, $body)->assertOk();
        $this->assertSame([], $response->headers->getCookies());
        $this->assertDatabaseHas('identity_sessions', ['id' => 'one', 'context_version' => 2]);
        $this->assertDatabaseHas('identity_sessions', ['id' => 'two', 'context_version' => 1]);
        $headers['HTTP_X_IDENTITY_SIGNATURE'] = 'v1='.hash_hmac('sha256', 'same-id.'.$timestamp.'.'.$body, str_repeat('b', 32));
        $this->call('POST', 'https://second.test/identity/events', [], [], [], $headers, $body)->assertOk();
        $this->assertDatabaseHas('identity_sessions', ['id' => 'two', 'context_version' => 2]);
        $this->assertDatabaseCount('identity_inbox', 2);
    }

    public function test_package_facade_does_not_reuse_another_requests_authority(): void
    {
        $identity = app(Identity::class);
        foreach (['one' => 11, 'two' => 22] as $name => $version) {
            $graph = $identity->consumer($name);
            IdentitySession::create(['id' => $name, 'binding_hash' => $graph->context->bindingHash(), 'user_id' => null, 'subject' => 'person', 'sid' => 'source', 'token_vault' => $graph->make(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:'.$name), 'selection' => [], 'context_version' => $version, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        }
        Route::middleware('web')->get('/facade-probe', function (Request $request) {
            $request->session()->put('identity.session', $request->attributes->get('identity.consumer'));

            return response()->json(['version' => \IdentityPlatform\Laravel\Facades\Identity::contextVersion()]);
        });
        $this->getJson('https://consumer.test/facade-probe')->assertOk()->assertJsonPath('version', 11);
        $this->getJson('https://second.test/facade-probe')->assertOk()->assertJsonPath('version', 22);
        $this->getJson('https://consumer.test/facade-probe')->assertOk()->assertJsonPath('version', 11);
    }
}
