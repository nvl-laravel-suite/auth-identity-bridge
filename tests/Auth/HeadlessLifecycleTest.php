<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Auth;

use Closure;
use IdentityPlatform\Laravel\Auth\AuthStatePresenter;
use IdentityPlatform\Laravel\Auth\BrowserLifecycle;
use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Events\AuthenticatedSessionEstablished;
use IdentityPlatform\Laravel\Events\ContextSelected;
use IdentityPlatform\Laravel\Events\LocalSessionEnded;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Http\Controllers\BrowserController;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Sessions\LocalSessionDirectory;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserProjectionRepository;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\Oidc\ProviderFixture;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;

class InterleavedPresentationProjection extends UserProjectionRepository
{
    public Closure $afterProjection;

    public function find(?string $id): ?IdentityUser
    {
        $profile = parent::find($id);
        ($this->afterProjection)();

        return $profile;
    }
}

class HeadlessLifecycleTest extends TestCase
{
    private ProviderFixture $provider;

    private array $choices = [[]];

    private int $contextsStatus = 200;

    private int $contextsCalls = 0;

    private int $snapshotCalls = 0;

    private ?Closure $duringContexts = null;

    private ?Closure $duringSnapshot = null;

    private ?Closure $duringToken = null;

    protected function setUp(): void
    {
        parent::setUp();
        $this->configure(['identity.consumers.one.origin' => ProviderFixture::ORIGIN, 'identity.consumers.one.application_id' => 'app-demo', 'identity.consumers.one.browser.client_id' => 'web-demo']);
        $this->provider = new ProviderFixture;
        Http::fake(function (HttpRequest $request) {
            if ($request->url() === ProviderFixture::ORIGIN.'/api/authorization/contexts') {
                $this->contextsCalls++;
                if ($this->duringContexts) {
                    ($this->duringContexts)();
                }

                return Http::response($this->contexts(), $this->contextsStatus);
            }
            if ($request->url() === ProviderFixture::ORIGIN.'/api/authorization/snapshot') {
                $this->snapshotCalls++;
                if ($this->duringSnapshot) {
                    ($this->duringSnapshot)();
                }

                return Http::response($this->snapshot());
            }
            if ($request->url() === ProviderFixture::ISSUER.'/oauth2/token' && $this->duringToken) {
                ($this->duringToken)();
            }
            if ($request->url() === ProviderFixture::ISSUER.'/oauth2/revoke') {
                return Http::response([]);
            }

            return null;
        });
        $this->provider->fake();
    }

    private function browser(string $method = 'GET'): Request
    {
        $request = Request::create('https://consumer.test/protected', $method);
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        $request->setLaravelSession($store);

        return $request;
    }

    private function start(SessionManager $manager, Request $request): array
    {
        parse_str((string) parse_url($manager->start($request, '/documents'), PHP_URL_QUERY), $query);
        $this->provider->claims['nonce'] = $query['nonce'];

        return ['state' => $query['state'], 'code' => 'synthetic-code'];
    }

    private function login(Request $request): SessionManager
    {
        $manager = app(SessionManager::class);
        $this->assertSame('/auth/contexts', $manager->complete($request, $this->start($manager, $request)));

        return $manager;
    }

    private function row(Request $request): IdentitySession
    {
        return IdentitySession::query()->findOrFail($request->session()->get('identity.session'));
    }

    private function contexts(): array
    {
        return [
            'contract' => 'platform-authorization-contexts.v1', 'issuer' => ProviderFixture::ISSUER,
            'subject' => 'person-demo', 'central_session_id' => 'central-session-demo', 'application_id' => 'app-demo', 'client_id' => 'web-demo',
            'contexts' => array_map(fn ($selection) => ['selection' => $selection, 'applicationName' => 'Synthetic app', 'organizationName' => null, 'roleName' => null], $this->choices),
            'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59),
        ];
    }

    private function snapshot(): array
    {
        return [
            'contract' => 'platform-authorization-snapshot.v1', 'issuer' => ProviderFixture::ISSUER,
            'subject' => 'person-demo', 'central_session_id' => 'central-session-demo', 'application_id' => 'app-demo', 'client_id' => 'web-demo',
            'principal_kind' => 'user', 'session_status' => 'active', 'security_version' => 1,
            'identity_status' => 'active', 'application_status' => 'active', 'grant_status' => 'active',
            'organization_id' => null, 'selected_role_id' => null, 'client_policy_version' => 1,
            'role_ids' => [], 'roles' => [], 'permissions' => ['documents.read'], 'authz_version' => 1, 'application_policy_version' => 1,
            'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59),
            'assurance' => ['central_session_id' => 'central-session-demo', 'method' => 'totp_or_recovery', 'verified_at' => gmdate('Y-m-d\TH:i:s\Z')], 'delegation' => null,
        ];
    }

    private function lifecycle(): BrowserLifecycle
    {
        self::assertTrue(class_exists(BrowserLifecycle::class), 'Public headless lifecycle is missing');

        return $this->graph()->make(BrowserLifecycle::class);
    }

    private function prepareCallback(Request $request): array
    {
        $callback = $this->start(app(SessionManager::class), $request);
        $request->query->replace($callback);
        $request->server->set('QUERY_STRING', http_build_query($callback));

        return $callback;
    }

    public function test_public_completion_selects_real_verified_context_and_events_observe_committed_state_once(): void
    {
        $api = $this->lifecycle();
        $request = $this->browser();
        $this->bindRequest($request);
        $events = [];
        $observed = [];
        Event::listen(AuthenticatedSessionEstablished::class, function ($event) use (&$events, &$observed): void {
            $observed[] = IdentitySession::count();
            $events[] = $event;
            throw new \RuntimeException('Optional notification failed');
        });
        Event::listen(ContextSelected::class, function ($event) use (&$events, &$observed): void {
            $observed[] = IdentitySession::firstOrFail()->context_version;
            $events[] = $event;
        });
        $callback = $this->prepareCallback($request);
        self::assertSame('/auth/contexts', $api->completeSignIn($request));
        $request->setMethod('POST');
        $request->headers->set('Origin', 'https://consumer.test');
        $request->merge(['context_version' => 1, '_token' => $request->session()->token()]);
        self::assertSame('/documents', $api->selectContext($request)->url);
        self::assertCount(2, $events);
        self::assertSame([1, 2], $observed);
        self::assertSame('one', $events[0]->consumer);
        self::assertSame('person-demo', $events[0]->actorSubject);
        self::assertStringNotContainsString('token', json_encode($events, JSON_THROW_ON_ERROR));
        try {
            $api->completeSignIn($request);
            self::fail('Callback replay accepted');
        } catch (IdentityException $error) {
            self::assertSame('invalid_login_state', $error->errorCode);
        }
        self::assertCount(1, $this->provider->tokenForms());
        self::assertCount(2, $events);
    }

    public function test_raw_duplicate_array_and_long_callbacks_refuse_before_consuming_intent(): void
    {
        $api = $this->lifecycle();
        $request = $this->browser();
        $callback = $this->prepareCallback($request);
        foreach (['&%73tate=second', '&state[]=array', '&x='.str_repeat('x', 16384)] as $suffix) {
            $request->server->set('QUERY_STRING', http_build_query($callback).$suffix);
            try {
                $api->completeSignIn($request);
                self::fail('Malformed callback accepted');
            } catch (IdentityException $error) {
                self::assertSame('callback_invalid', $error->errorCode);
            }
        }
        self::assertCount(0, $this->provider->tokenForms());
        $request->server->set('QUERY_STRING', http_build_query($callback));
        self::assertSame('/auth/contexts', $api->completeSignIn($request));
    }

    /** @param  array<string, string>  $callback */
    private function respond(Request $request, array $callback): void
    {
        $request->query->replace($callback);
        $request->server->set('QUERY_STRING', http_build_query($callback));
    }

    public function test_declined_sign_in_consumes_its_transaction_and_returns_to_the_start_without_exchange(): void
    {
        $api = $this->lifecycle();
        $request = $this->browser();
        $callback = $this->prepareCallback($request);
        Event::fake([AuthenticatedSessionEstablished::class]);
        // Identity's "Back to {app}": a standard error response carrying the consumer's own state.
        $this->respond($request, ['error' => 'access_denied', 'state' => $callback['state']]);
        self::assertSame('/documents', $api->completeSignIn($request));
        self::assertCount(0, $this->provider->tokenForms());
        self::assertSame(0, IdentitySession::count());
        Event::assertNotDispatched(AuthenticatedSessionEstablished::class);
        try {
            $api->completeSignIn($request);
            self::fail('Declined callback replay accepted');
        } catch (IdentityException $error) {
            self::assertSame('invalid_login_state', $error->errorCode);
        }
    }

    public function test_decline_without_a_live_transaction_is_rejected(): void
    {
        $api = $this->lifecycle();
        $request = $this->browser();
        $this->prepareCallback($request);
        $this->respond($request, ['error' => 'access_denied', 'state' => 'forged-state']);
        try {
            $api->completeSignIn($request);
            self::fail('Forged decline accepted');
        } catch (IdentityException $error) {
            self::assertSame('invalid_login_state', $error->errorCode);
        }
        self::assertSame(0, IdentitySession::count());
    }

    public function test_decline_from_another_issuer_or_with_a_code_is_not_a_return(): void
    {
        foreach ([['iss' => 'https://other-issuer.test'], ['code' => 'synthetic-code']] as $extra) {
            $api = $this->lifecycle();
            $request = $this->browser();
            $callback = $this->prepareCallback($request);
            $this->respond($request, ['error' => 'access_denied', 'state' => $callback['state']] + $extra);
            try {
                $api->completeSignIn($request);
                self::fail('Ambiguous decline accepted');
            } catch (IdentityException $error) {
                self::assertSame('oidc_callback_invalid', $error->errorCode);
            }
        }
        self::assertCount(0, $this->provider->tokenForms());
        self::assertSame(0, IdentitySession::count());
    }

    public function test_other_authorization_errors_remain_failures(): void
    {
        $api = $this->lifecycle();
        $request = $this->browser();
        $callback = $this->prepareCallback($request);
        $this->respond($request, ['error' => 'server_error', 'state' => $callback['state']]);
        try {
            $api->completeSignIn($request);
            self::fail('Provider error accepted');
        } catch (IdentityException $error) {
            self::assertSame('oidc_callback_invalid', $error->errorCode);
        }
        self::assertCount(0, $this->provider->tokenForms());
        self::assertSame(0, IdentitySession::count());
    }

    public function test_failed_login_emits_no_authenticated_event(): void
    {
        $api = $this->lifecycle();
        $request = $this->browser();
        $this->prepareCallback($request);
        $this->choices = [];
        Event::fake([AuthenticatedSessionEstablished::class]);
        try {
            $api->completeSignIn($request);
            self::fail('Ineligible login accepted');
        } catch (IdentityException $error) {
            self::assertSame('access_denied', $error->errorCode);
        }
        Event::assertNotDispatched(AuthenticatedSessionEstablished::class);
        self::assertSame(0, IdentitySession::count());
    }

    public function test_expired_logout_is_authoritative_despite_throwing_listener_and_central_callback_is_one_use(): void
    {
        $api = $this->lifecycle();
        $request = $this->browser();
        $this->login($request);
        $this->row($request)->update(['expires_at' => now()->subSecond()]);
        $ended = 0;
        Event::listen(LocalSessionEnded::class, function () use (&$ended): void {
            $ended++;
            throw new \RuntimeException('Failed optional notification');
        });
        $request->setMethod('POST');
        $request->headers->set('Origin', 'https://consumer.test');
        $request->merge(['_token' => $request->session()->token()]);
        parse_str(parse_url($api->centralSignOut($request), PHP_URL_QUERY), $query);
        self::assertSame(1, $ended);
        self::assertSame(0, IdentitySession::count());
        self::assertNull($request->session()->get('identity.session'));
        $request->query->replace(['state' => $query['state']]);
        $request->server->set('QUERY_STRING', http_build_query(['state' => $query['state']]));
        $api->finishLogout($request);
        $this->expectException(IdentityException::class);
        $api->finishLogout($request);
    }

    public function test_state_uses_safe_binding_display_and_current_decision_only(): void
    {
        $this->lifecycle();
        $request = $this->browser();
        $manager = $this->login($request);
        $manager->select($request, [], 1);
        $this->bindRequest($request);
        IdentityUser::query()->update(['name' => 'Other binding private name', 'email' => 'other@example.test']);
        $state = $this->graph()->make(AuthStatePresenter::class)->current();
        self::assertSame('person-demo', $state->actor->subject);
        self::assertSame('Synthetic Person', $state->actor->name);
        self::assertSame($state->actor, $state->effectiveSubject);
        self::assertSame(['documents.read'], $state->decision->permissions);
        self::assertSame(2, $state->contextVersion);
        self::assertNull($state->applicationContext);
        $json = json_encode($state, JSON_THROW_ON_ERROR);
        foreach (['token', 'vault', 'central-session-demo', 'Other binding', 'security_version', 'snapshot'] as $private) {
            self::assertStringNotContainsString($private, $json);
        }
    }

    public function test_state_fails_closed_if_source_changes_during_decision_fetch(): void
    {
        $this->lifecycle();
        $request = $this->browser();
        $manager = $this->login($request);
        $manager->select($request, [], 1);
        $this->bindRequest($request);
        $this->duringSnapshot = fn () => IdentitySession::query()->update(['sid' => 'different-source']);
        $state = $this->graph()->make(AuthStatePresenter::class)->current();
        self::assertNull($state->actor);
        self::assertSame([], $state->decision->permissions);
        self::assertNull($state->contextVersion);
    }

    public function test_notifications_follow_outer_commit_and_rollback_discards_them(): void
    {
        $api = $this->lifecycle();
        $request = $this->browser();
        $this->prepareCallback($request);
        $seen = [];
        Event::listen(AuthenticatedSessionEstablished::class, function ($event) use (&$seen): void {
            $seen[] = $event;
        });
        $connection = (new IdentitySession)->getConnection();
        $connection->beginTransaction();
        $api->completeSignIn($request);
        self::assertSame([], $seen);
        $connection->commit();
        self::assertCount(1, $seen);
        $other = $this->browser();
        $this->prepareCallback($other);
        $connection->beginTransaction();
        $api->completeSignIn($other);
        $connection->rollBack();
        self::assertCount(1, $seen);
        self::assertSame(1, IdentitySession::count());
    }

    public function test_public_commands_refuse_wrong_origin_missing_csrf_and_stale_context(): void
    {
        $api = $this->lifecycle();
        $request = $this->browser('POST');
        $manager = $this->login($request);
        foreach ([['https://foreign.test', $request->session()->token(), 'origin_refused'], ['https://consumer.test', 'incorrect', 'csrf_refused']] as [$origin, $token, $expected]) {
            $request->headers->set('Origin', $origin);
            $request->merge(['_token' => $token, 'context_version' => 1]);
            try {
                $api->selectContext($request);
                self::fail('Unsafe context command accepted');
            } catch (IdentityException $error) {
                self::assertSame($expected, $error->errorCode);
            }
        }
        $request->merge(['_token' => $request->session()->token(), 'context_version' => 2]);
        try {
            $api->selectContext($request);
            self::fail('Stale context command accepted');
        } catch (IdentityException $error) {
            self::assertSame('context_changed', $error->errorCode);
        }
        self::assertSame(1, $this->row($request)->context_version);
    }

    public function test_unselected_state_refuses_a_browser_pointer_changed_during_projection(): void
    {
        $request = $this->browser();
        $this->login($request);
        $this->bindRequest($request);
        $projection = $this->graph()->make(InterleavedPresentationProjection::class);
        $projection->afterProjection = fn () => $request->session()->forget('identity.session');
        $this->graph()->instance(UserProjectionRepository::class, $projection);
        $state = $this->graph()->make(AuthStatePresenter::class)->current();
        self::assertNull($state->actor);
        self::assertNull($state->contextVersion);
        self::assertSame([], $state->decision->permissions);
    }

    public function test_unselected_state_refuses_new_delegation_mode_during_projection(): void
    {
        $request = $this->browser();
        $this->login($request);
        $this->bindRequest($request);
        $projection = $this->graph()->make(InterleavedPresentationProjection::class);
        $projection->afterProjection = function () use ($request): void {
            app(OverlayRepository::class)->save($this->row($request)->id, ['source_sid' => 'central-session-demo', 'status' => 'pending', 'browser_binding' => 'synthetic', 'context_version' => 1, 'decision' => ['subject' => ['id' => 'subject-2']], 'expires_at' => now()->addMinute()]);
        };
        $this->graph()->instance(UserProjectionRepository::class, $projection);
        self::assertNull($this->graph()->make(AuthStatePresenter::class)->current()->actor);
    }

    public function test_explicit_target_flow_creates_its_own_intent_and_refuses_source_callback(): void
    {
        $source = $this->browser('POST');
        $source->headers->set('Origin', 'https://consumer.test');
        $source->session()->regenerateToken();
        $source->merge(['_token' => $source->session()->token()]);
        parse_str(parse_url($this->lifecycle()->startSignIn($source, '/source-only'), PHP_URL_QUERY), $sourceQuery);
        $definition = config('identity');
        $definition['consumers']['two'] = $definition['consumers']['one'];
        $target = &$definition['consumers']['two'];
        $target['app_origin'] = 'https://second.test';
        $target['browser']['redirect_uri'] = 'https://second.test/auth/callback';
        $target['browser']['post_logout_redirect_uri'] = 'https://second.test/signed-out';
        $target['routes']['event_uri'] = 'https://second.test/identity/events';
        $target['routes']['backchannel_logout_uri'] = 'https://second.test/identity/backchannel-logout';
        $target['routes']['guard'] = 'identity_two';
        $target['session']['cookie'] = '__Host-two';
        $target['browser']['client_id'] = 'web-two';
        unset($target);
        $this->configure(['identity' => $definition]);
        $this->selectConsumer();
        $targetRequest = Request::create('https://second.test/auth/sign-in', 'POST');
        $store = new Store('__Host-two', new ArraySessionHandler(120));
        $store->start();
        $store->regenerateToken();
        $targetRequest->setLaravelSession($store);
        $targetRequest->headers->set('Origin', 'https://second.test');
        $targetRequest->merge(['_token' => $store->token()]);
        $targetApi = app(Identity::class)->consumer('two', $targetRequest)->make(BrowserLifecycle::class);
        parse_str(parse_url($targetApi->startSignIn($targetRequest), PHP_URL_QUERY), $targetQuery);
        self::assertSame('web-two', $targetQuery['client_id']);
        self::assertSame('https://second.test/auth/callback', $targetQuery['redirect_uri']);
        self::assertNotSame($sourceQuery['state'], $targetQuery['state']);
        self::assertNotSame($sourceQuery['nonce'], $targetQuery['nonce']);
        self::assertNotSame($source->session()->getId(), $targetRequest->session()->getId());
        self::assertNull($targetRequest->session()->get('identity.session'));
        $targetRequest->query->replace(['state' => $sourceQuery['state'], 'code' => 'synthetic-code']);
        $targetRequest->server->set('QUERY_STRING', http_build_query($targetRequest->query()));
        try {
            $targetApi->completeSignIn($targetRequest);
            self::fail('Source intent accepted by target');
        } catch (IdentityException $error) {
            self::assertSame('invalid_login_state', $error->errorCode);
        }
        self::assertCount(0, $this->provider->tokenForms());
    }

    public function test_replacement_login_ends_old_local_session_once_before_new_establishment(): void
    {
        $request = $this->browser();
        $this->login($request);
        $old = $this->row($request)->id;
        $ended = [];
        Event::listen(LocalSessionEnded::class, function ($event) use (&$ended): void {
            $ended[] = $event;
        });
        $this->prepareCallback($request);
        $this->lifecycle()->completeSignIn($request);
        self::assertCount(1, $ended);
        self::assertNull(IdentitySession::find($old));
        self::assertSame(1, IdentitySession::count());
    }

    public function test_owned_session_revocation_notifies_after_commit_and_foreign_owner_does_not(): void
    {
        $request = $this->browser();
        $this->login($request);
        $row = $this->row($request);
        $owner = IdentityUser::findOrFail($row->user_id);
        $directory = $this->graph()->make(LocalSessionDirectory::class);
        $seen = [];
        Event::listen(LocalSessionEnded::class, function ($event) use (&$seen): void {
            $seen[] = $event;
            throw new \RuntimeException('Optional listener failed');
        });
        $foreign = IdentityUser::create(['identity_key' => hash('sha256', 'other'), 'issuer' => ProviderFixture::ISSUER, 'subject' => 'other']);
        self::assertFalse($directory->revoke($foreign, $row->id));
        self::assertSame([], $seen);
        $connection = $row->getConnection();
        $connection->beginTransaction();
        self::assertTrue($directory->revoke($owner, $row->id));
        self::assertSame([], $seen);
        $connection->commit();
        self::assertCount(1, $seen);
        self::assertNull(IdentitySession::find($row->id));
        self::assertFalse($directory->revoke($owner, $row->id));
        self::assertCount(1, $seen);
    }

    public function test_nonwriter_state_presents_its_own_binding_facts_without_borrowing_shared_profile(): void
    {
        $sourceRequest = $this->browser();
        $this->login($sourceRequest);
        $shared = IdentityUser::firstOrFail();
        $definition = config('identity');
        $definition['consumers']['two'] = $definition['consumers']['one'];
        $target = &$definition['consumers']['two'];
        $target['app_origin'] = 'https://second.test';
        $target['browser']['redirect_uri'] = 'https://second.test/auth/callback';
        $target['browser']['post_logout_redirect_uri'] = 'https://second.test/signed-out';
        $target['routes']['event_uri'] = 'https://second.test/identity/events';
        $target['routes']['backchannel_logout_uri'] = 'https://second.test/identity/backchannel-logout';
        $target['routes']['guard'] = 'identity_two';
        $target['session']['cookie'] = '__Host-two';
        unset($target);
        $this->configure(['identity' => $definition]);
        $this->selectConsumer();
        $request = Request::create('https://second.test/');
        $store = new Store('__Host-two', new ArraySessionHandler(120));
        $store->start();
        $store->put('identity.session', 'target-local');
        $request->setLaravelSession($store);
        $graph = app(Identity::class)->consumer('two', $request);
        $projection = $graph->make(UserSynchronizer::class)->sync(['sub' => 'person-demo', 'name' => 'Second binding display', 'email' => 'second@example.test']);
        $graph->make(SessionRepository::class)->create(['id' => 'target-local', 'user_id' => $projection->id, 'subject' => 'person-demo', 'sid' => 'target-source',
            'token_vault' => $graph->make(IdentityVault::class)->seal(['access_token' => 'synthetic-target', 'expires_at' => time() + 300], 'session:target-local'),
            'selection' => [], 'context_version' => 1, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        self::assertSame('Synthetic Person', $shared->refresh()->name);
        $state = $graph->make(AuthStatePresenter::class)->current();
        self::assertSame('Second binding display', $state->actor?->name);
        self::assertSame('second@example.test', $state->actor?->email);
        self::assertSame('two', $state->consumer);
        self::assertSame([], $state->decision->permissions);
    }

    public function test_default_controller_exposes_allowlisted_json_and_browser_selection_redirects(): void
    {
        $request = $this->browser('POST');
        $this->login($request);
        $this->bindRequest($request);
        $request->headers->set('Origin', 'https://consumer.test');
        $request->headers->set('Accept', 'application/json');
        $request->merge(['_token' => $request->session()->token(), 'context_version' => 1]);
        $controller = $this->graph()->make(BrowserController::class);
        self::assertSame(['contexts', 'contextVersion'], array_keys($controller->contexts($request)->getData(true)));
        $response = $controller->select($request);
        self::assertSame(['destination' => ['kind' => 'local', 'url' => '/documents', 'consumer' => null]], $response->getData(true));
        $request->headers->set('Accept', 'text/html');
        $request->merge(['_token' => $request->session()->token(), 'context_version' => 2]);
        $response = $controller->select($request);
        self::assertSame(303, $response->getStatusCode());
        self::assertSame('/', $response->headers->get('Location'));
    }
}
