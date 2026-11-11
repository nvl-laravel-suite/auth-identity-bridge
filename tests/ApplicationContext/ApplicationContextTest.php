<?php

namespace IdentityPlatform\Laravel\Tests\ApplicationContext;

use Carbon\CarbonImmutable;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextManager;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextProvider;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextRegistry;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextResource;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextScope;
use IdentityPlatform\Laravel\Auth\AuthStatePresenter;
use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner;
use IdentityPlatform\Laravel\Authorization\Principal;
use IdentityPlatform\Laravel\Callbacks\CallbackRepository;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Http\Controllers\ApplicationContextController;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\Oidc\ProviderFixture;
use IdentityPlatform\Laravel\Tests\Support\NativeJsonOrder;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;

class ApplicationContextTest extends TestCase
{
    private Request $request;

    private IdentitySession $source;

    protected function setUp(): void
    {
        parent::setUp();
        if (! class_exists(ApplicationContextManager::class)) {
            return;
        }
        $owner = app(UserSynchronizer::class)->sync(['sub' => 'actor', 'name' => 'Actor']);
        $this->source = app(SessionRepository::class)->create(['id' => 'source', 'user_id' => $owner->id, 'subject' => 'actor', 'sid' => 'central-source',
            'token_vault' => app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:source'),
            'selection' => ['selected' => true], 'context_version' => 2, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $this->request = Request::create('https://consumer.test/auth/application-context', 'POST', ['context_version' => 2, 'kind' => 'workspace', 'resourceId' => 'one']);
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        $store->regenerateToken();
        $store->put('identity.session', 'source');
        $this->request->setLaravelSession($store);
        $this->request->headers->set('Origin', 'https://consumer.test');
        $this->request->merge(['_token' => $store->token()]);
        $this->bindRequest($this->request);
        app(ApplicationContextRegistry::class)->register('one', 'workspace', WorkspaceFixture::class);
        app(ApplicationContextRegistry::class)->register('one', 'case', CaseFixture::class);
        Schema::create('p10_resources', function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('label');
            $table->string('version');
        });
        Schema::create('p10_memberships', function (Blueprint $table): void {
            $table->string('resource_id');
            $table->string('binding_hash');
            $table->string('actor');
            $table->string('version');
        });
        DB::table('p10_resources')->insert([['id' => 'one', 'label' => 'Workspace One', 'version' => 'v1'], ['id' => 'two', 'label' => 'Workspace Two', 'version' => 'v2']]);
        DB::table('p10_memberships')->insert(array_map(fn ($id) => ['resource_id' => $id, 'binding_hash' => app(IdentityConfig::class)->bindingHash(), 'actor' => 'actor', 'version' => 'm1'], ['one', 'two']));
        WorkspaceFixture::$duringResolve = null;
        Http::preventStrayRequests();
        Http::fake(['https://identity.test/api/authorization/snapshot' => Http::response($this->snapshot()), 'https://identity.test/api/authorization/contexts' => Http::response([
            'contract' => 'platform-authorization-contexts.v1', 'issuer' => 'https://identity.test/api/auth', 'subject' => 'actor', 'central_session_id' => 'central-source', 'application_id' => 'app-1', 'client_id' => 'web-1',
            'contexts' => [['selection' => [], 'applicationName' => 'App', 'organizationName' => null, 'roleName' => null]], 'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59),
        ])]);
    }

    private function snapshot(): array
    {
        return ['contract' => 'platform-authorization-snapshot.v1', 'issuer' => 'https://identity.test/api/auth', 'subject' => 'actor', 'central_session_id' => 'central-source', 'application_id' => 'app-1', 'client_id' => 'web-1', 'principal_kind' => 'user', 'session_status' => 'active', 'security_version' => 1, 'identity_status' => 'active', 'application_status' => 'active', 'grant_status' => 'active', 'organization_id' => null, 'selected_role_id' => null, 'client_policy_version' => 1, 'role_ids' => [], 'roles' => [], 'permissions' => ['documents.update'], 'authz_version' => 1, 'application_policy_version' => 1, 'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59), 'assurance' => null, 'delegation' => null];
    }

    private function manager(): ApplicationContextManager
    {
        self::assertTrue(class_exists(ApplicationContextManager::class), 'Application resource context API missing');

        return app(ApplicationContextManager::class);
    }

    public function test_selection_persists_only_provider_facts_and_advances_existing_version(): void
    {
        $manager = $this->manager();
        self::assertCount(2, $manager->list($this->request, 'workspace'));
        $this->request->merge(['label' => 'Forged label', 'permissions' => ['admin']]);
        $context = $manager->select($this->request);
        self::assertSame('Workspace One', $context->label);
        self::assertSame(3, $this->source->fresh()->context_version);
        self::assertSame('one', $manager->current($this->request)->resourceId);
        self::assertStringNotContainsString('permissions', json_encode($this->source->fresh()->application_context));
        $this->request->setMethod('GET');
        $state = app(AuthStatePresenter::class)->current();
        self::assertSame(3, $state->contextVersion);
        self::assertSame('Workspace One', $state->applicationContext['label']);
        self::assertSame(['kind', 'resourceId', 'label', 'consumerBinding', 'actorSubject', 'providerSelection', 'version', 'expiresAt'], array_keys($state->applicationContext));
        self::assertSame(app(IdentityConfig::class)->bindingHash(), $state->applicationContext['consumerBinding']);
        self::assertSame('actor', $state->applicationContext['actorSubject']);
        self::assertSame(['organizationId' => null, 'roleId' => null], $state->applicationContext['providerSelection']);
        foreach (['bindingHash', 'central-source', 'userId', '"sourceId"'] as $private) {
            self::assertStringNotContainsString($private, json_encode($state->applicationContext));
        }
    }

    public function test_selection_survives_native_json_reordering_of_its_stored_scope(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        $stored = DB::table('identity_sessions')->where('id', 'source')->value('application_context');
        self::assertIsString($stored);
        $reordered = NativeJsonOrder::encode(json_decode($stored, true, flags: JSON_THROW_ON_ERROR));
        self::assertNotSame($stored, $reordered);
        DB::table('identity_sessions')->where('id', 'source')->update(['application_context' => $reordered]);

        self::assertSame('one', $manager->current($this->request)?->resourceId);
        self::assertSame(3, $this->source->fresh()->context_version);
    }

    public function test_stale_selection_version_and_forged_resource_are_refused(): void
    {
        $manager = $this->manager();
        $this->request->merge(['resourceId' => 'foreign']);
        try {
            $manager->select($this->request);
            self::fail();
        } catch (IdentityException $e) {
            self::assertSame('application_context_unavailable', $e->errorCode);
        }
        $this->request->merge(['resourceId' => 'one', 'context_version' => 1]);
        $this->expectExceptionObject(new IdentityException('context_changed', 409));
        $manager->select($this->request);
    }

    public function test_deleted_membership_and_changed_local_version_clear_and_bump(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        DB::table('p10_memberships')->where('resource_id', 'one')->delete();
        self::assertNull($manager->current($this->request));
        self::assertNull($this->source->fresh()->application_context);
        self::assertSame(4, $this->source->fresh()->context_version);
        $this->request->merge(['context_version' => 4, 'resourceId' => 'two']);
        $manager->select($this->request);
        DB::table('p10_memberships')->where('resource_id', 'two')->update(['version' => 'm2']);
        self::assertNull($manager->current($this->request));
        self::assertSame(6, $this->source->fresh()->context_version);
    }

    public function test_two_domains_do_not_confuse_identical_resource_ids(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        $this->request->merge(['context_version' => 3, 'kind' => 'case']);
        self::assertSame('Support case', $manager->select($this->request)->label);
        self::assertSame('case', $manager->current($this->request)->kind);
        self::assertSame(4, $this->source->fresh()->context_version);
    }

    public function test_commands_require_post_exact_origin_and_csrf(): void
    {
        $manager = $this->manager();
        foreach ([['GET', 'https://consumer.test', 'correct', 'origin_refused'], ['POST', 'https://foreign.test', 'correct', 'origin_refused'], ['POST', 'https://consumer.test', 'wrong', 'csrf_refused']] as [$method,$origin,$token,$code]) {
            $this->request->setMethod($method);
            $this->request->headers->set('Origin', $origin);
            $this->request->merge(['_token' => $token === 'correct' ? $this->request->session()->token() : $token]);
            try {
                $manager->select($this->request);
                self::fail();
            } catch (IdentityException $e) {
                self::assertSame($code, $e->errorCode);
            }
        }
        self::assertNull($this->source->fresh()->application_context);
    }

    public function test_provider_selection_clears_resource_in_the_same_version_transition(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        app(SessionManager::class)->select($this->request, [], 3);
        self::assertNull($this->source->fresh()->application_context);
        self::assertSame(4, $this->source->fresh()->context_version);
    }

    public function test_expiry_clears_without_silent_renewal(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        $this->travel(301)->seconds();
        // Keep the token independently live; this checks the bounded remembered descriptor.
        $this->source->update(['token_vault' => app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => now()->timestamp + 500], 'session:source')]);
        self::assertNull($manager->current($this->request));
        self::assertSame(4, $this->source->fresh()->context_version);
    }

    public function test_assertion_revalidates_membership_after_host_locks_inside_existing_runner(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        $this->request->merge(['context_version' => 3]);
        $mutated = false;
        try {
            app(OrdinaryActionRunner::class)->run($this->request, function () {
                DB::table('p10_memberships')->where('resource_id', 'one')->delete();

                return null;
            }, function ($resource, $principal) use ($manager, &$mutated) {
                $manager->assertEligible($this->request, $principal);
                $mutated = true;
            });
            self::fail();
        } catch (IdentityException $e) {
            self::assertSame('application_context_unavailable', $e->errorCode);
        }
        self::assertFalse($mutated);
    }

    public function test_context_change_during_held_write_rolls_back_the_write_and_change(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        $this->request->merge(['context_version' => 3]);
        try {
            app(OrdinaryActionRunner::class)->run($this->request, fn () => null, function () use ($manager) {
                $manager->clear($this->request);
            });
            self::fail();
        } catch (IdentityException $e) {
            self::assertSame('context_changed', $e->errorCode);
        }
        self::assertSame(3, $this->source->fresh()->context_version);
        self::assertSame('one', $manager->current($this->request)->resourceId);
    }

    public function test_presenter_cannot_tag_old_context_with_a_new_version(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        WorkspaceFixture::$duringResolve = fn () => IdentitySession::whereKey('source')->increment('context_version');
        $this->request->setMethod('GET');
        $state = app(AuthStatePresenter::class)->current();
        self::assertNull($state->applicationContext);
        self::assertNull($state->contextVersion);
    }

    public function test_overlay_modes_never_inherit_or_select_application_context(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        app(OverlayRepository::class)->save('source', ['source_sid' => 'central-source', 'status' => 'pending', 'browser_binding' => 'synthetic', 'context_version' => 3, 'decision' => ['subject' => ['id' => 'subject']], 'expires_at' => now()->subSecond()]);
        self::assertNull($manager->current($this->request));
        $this->request->merge(['context_version' => 3]);
        $this->expectExceptionObject(new IdentityException('ordinary_action_required', 403));
        $manager->select($this->request);
    }

    public function test_registry_boot_registration_survives_graph_prewarm_and_resolves_provider_in_that_graph(): void
    {
        $registry = app(ApplicationContextRegistry::class);
        $registry->register('one', 'prewarmed', ScopedFixture::class);
        // An ambient host singleton must not leak into consumer-local provider construction.
        $this->app->singleton(ScopedFixture::class);
        $ambient = app(ScopedFixture::class);
        $this->selectConsumer();
        $this->bindRequest($this->request);
        self::assertSame($registry, $this->graph()->make(ApplicationContextRegistry::class));
        self::assertNotSame($ambient, $this->graph()->make(ScopedFixture::class));
        self::assertSame('one', $this->manager()->list($this->request, 'prewarmed')[0]->label);
    }

    public function test_source_actor_and_provider_selection_changes_never_reuse_remembered_context(): void
    {
        $manager = $this->manager();
        foreach ([['sid' => 'changed-source'], ['subject' => 'changed-actor'], ['selection' => ['selected' => true, 'organizationId' => 'other-org']], ['selection' => ['selected' => true, 'roleId' => 'other-role']]] as $change) {
            $this->source->refresh()->update(['sid' => 'central-source', 'subject' => 'actor', 'selection' => ['selected' => true]]);
            $this->request->merge(['context_version' => $this->source->fresh()->context_version]);
            $manager->select($this->request);
            $version = $this->source->fresh()->context_version;
            $this->source->refresh()->update($change);
            self::assertNull($manager->current($this->request));
            self::assertNull($this->source->fresh()->application_context);
            self::assertSame($version + 1, $this->source->fresh()->context_version);
        }
    }

    public function test_same_resource_id_cannot_borrow_another_consumer_binding_or_membership(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        $remembered = $this->source->fresh()->application_context;
        $this->configure(['identity.consumers.one.browser.client_id' => 'other-client']);
        $this->bindRequest($this->request);
        $attributes = $this->source->fresh()->getAttributes();
        unset($attributes['binding_hash'], $attributes['created_at'], $attributes['updated_at']);
        foreach (['selection', 'snapshot', 'application_context'] as $cast) {
            $attributes[$cast] = $this->source->fresh()->getAttribute($cast);
        }
        $attributes['id'] = 'target-source';
        $attributes['token_vault'] = app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:target-source');
        $target = app(SessionRepository::class)->create($attributes);
        $this->request->session()->put('identity.session', 'target-source');
        self::assertNull($this->manager()->current($this->request));
        self::assertNull($target->fresh()->application_context);
        self::assertSame($remembered, $this->source->fresh()->application_context);
        $this->request->merge(['context_version' => $target->fresh()->context_version]);
        $this->expectExceptionObject(new IdentityException('application_context_unavailable', 403));
        $this->manager()->select($this->request);
    }

    public function test_provider_event_clears_context_in_the_same_receipted_version_change(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        $event = ['event_id' => 'p10-event', 'type' => 'grant.updated', 'subject' => 'actor'];
        $repository = app(CallbackRepository::class);
        $repository->event($event, hash('sha256', 'synthetic-event'));
        self::assertNull($this->source->fresh()->application_context);
        self::assertSame(4, $this->source->fresh()->context_version);
        $repository->event($event, hash('sha256', 'synthetic-event'));
        self::assertSame(4, $this->source->fresh()->context_version);
    }

    public function test_assertion_succeeds_only_inside_existing_fence_and_does_not_add_permissions(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        $this->request->merge(['context_version' => 3]);
        $context = app(OrdinaryActionRunner::class)->run($this->request, fn () => DB::table('p10_resources')->where('id', 'one')->lockForUpdate()->first(), function ($resource, $principal) use ($manager) {
            self::assertSame(['documents.update'], $principal->permissions());

            return $manager->assertEligible($this->request, $principal);
        });
        self::assertSame('one', $context->resourceId);
        $this->expectExceptionObject(new IdentityException('application_context_fence_required', 409));
        $manager->assertEligible($this->request, new Principal($this->snapshot()));
    }

    public function test_default_adapters_return_json_or_safe_browser_redirects_and_unknown_kind_refuses(): void
    {
        $controller = app(ApplicationContextController::class);
        self::assertCount(2, $controller->index($this->request)->getData(true)['contexts']);
        $this->request->headers->set('Accept', 'application/json');
        self::assertSame(['changed' => true, 'redirect' => '/'], $controller->select($this->request)->getData(true));
        self::assertSame('one', $controller->current($this->request)->getData(true)['applicationContext']['resourceId']);
        $this->request->merge(['context_version' => 3, 'return_to' => 'https://foreign.test/']);
        $this->request->headers->set('Accept', 'text/html');
        $response = $controller->clear($this->request);
        self::assertSame(303, $response->getStatusCode());
        self::assertSame('consumer.test', parse_url($response->headers->get('Location'), PHP_URL_HOST));
        self::assertStringNotContainsString('foreign.test', $response->headers->get('Location'));
        self::assertNull($this->source->fresh()->application_context);
        $this->expectExceptionObject(new IdentityException('application_context_unknown', 422));
        $this->manager()->list($this->request, 'unregistered');
    }

    public function test_resource_deleted_after_selection_is_cleared(): void
    {
        $manager = $this->manager();
        $manager->select($this->request);
        DB::table('p10_resources')->where('id', 'one')->delete();
        self::assertNull($manager->current($this->request));
        self::assertSame(4, $this->source->fresh()->context_version);
    }

    public function test_real_signed_token_refresh_preserves_same_scope_but_still_revalidates_membership(): void
    {
        $fixture = new ProviderFixture;
        $this->configure(['identity.consumers.one.origin' => $fixture::ORIGIN, 'identity.consumers.one.application_id' => 'app-demo', 'identity.consumers.one.browser.client_id' => 'web-demo']);
        $this->bindRequest($this->request);
        $fixture->claims['sub'] = 'actor';
        $fixture->claims['sid'] = 'central-source';
        $fixture->userinfo['sub'] = 'actor';
        $fixture->fake();
        $binding = app(IdentityConfig::class)->bindingHash();
        DB::table('p10_memberships')->update(['binding_hash' => $binding]);
        $tokens = ['access_token' => 'synthetic-access-token', 'refresh_token' => 'synthetic-refresh-token', 'subject' => 'actor', 'sid' => 'central-source', 'resource' => false, 'claims' => $fixture->claims, 'id_token' => $fixture->token($fixture->claims), 'expires_at' => time() + 300];
        $this->source->update(['user_id' => app(UserSynchronizer::class)->sync($fixture->userinfo)->id, 'binding_hash' => $binding, 'token_vault' => app(IdentityVault::class)->seal($tokens, 'session:source')]);
        $manager = $this->manager();
        $manager->select($this->request);
        $remembered = $this->source->fresh()->application_context;
        $tokens['expires_at'] = time() - 1;
        $this->source->refresh()->update(['token_vault' => app(IdentityVault::class)->seal($tokens, 'session:source')]);
        self::assertSame('one', $manager->current($this->request)->resourceId);
        self::assertSame(2, $this->source->fresh()->token_generation);
        self::assertSame(3, $this->source->fresh()->context_version);
        self::assertSame($remembered, $this->source->fresh()->application_context);
        self::assertCount(1, $fixture->tokenForms());
        DB::table('p10_memberships')->where('resource_id', 'one')->delete();
        self::assertNull($manager->current($this->request));
        self::assertSame(4, $this->source->fresh()->context_version);
    }

    public function test_registered_routes_use_existing_browser_session_and_origin_csrf_pipeline(): void
    {
        $this->withCredentials()->withSession(['identity.session' => 'source', '_token' => 'synthetic-csrf']);
        $this->getJson('https://consumer.test/auth/application-contexts?kind=workspace')->assertOk()->assertJsonCount(2, 'contexts');
        $this->postJson('https://consumer.test/auth/application-context', ['kind' => 'workspace', 'resourceId' => 'one', 'context_version' => 2, '_token' => 'synthetic-csrf'], ['Origin' => 'https://consumer.test'])->assertOk()->assertJsonPath('changed', true);
        $this->getJson('https://consumer.test/auth/application-context')->assertOk()->assertJsonPath('applicationContext.resourceId', 'one');
        $this->postJson('https://consumer.test/auth/application-context/clear', ['context_version' => 3, '_token' => 'wrong'], ['Origin' => 'https://consumer.test'])->assertStatus(419);
        $this->postJson('https://consumer.test/auth/application-context/clear', ['context_version' => 3, '_token' => 'synthetic-csrf'], ['Origin' => 'https://foreign.test'])->assertForbidden();
        $router = app('router');
        $router->setCompiledRoutes($router->getRoutes()->compile());
        $this->postJson('https://consumer.test/auth/application-context/clear', ['context_version' => 3, '_token' => 'synthetic-csrf'], ['Origin' => 'https://consumer.test'])->assertOk()->assertJsonPath('changed', true);
        $this->getJson('https://consumer.test/auth/application-context')->assertOk()->assertJsonPath('applicationContext', null);
    }

    public function test_signout_removes_the_remembered_context_with_its_source(): void
    {
        $this->manager()->select($this->request);
        Http::fake(['https://identity.test/api/auth/oauth2/revoke' => Http::response([])]);
        app(SessionManager::class)->logout($this->request);
        self::assertNull($this->source->fresh());
        self::assertNull($this->request->session()->get('identity.session'));
    }
}

class WorkspaceFixture implements ApplicationContextProvider
{
    public static ?\Closure $duringResolve = null;

    public function choices(ApplicationContextScope $scope): iterable
    {
        foreach (DB::table('p10_resources')->pluck('id') as $id) {
            if ($resource = $this->resolve($scope, $id, false)) {
                yield $resource;
            }
        }
    }

    public function resolve(ApplicationContextScope $scope, string $resourceId, bool $forUpdate): ?ApplicationContextResource
    {
        if (self::$duringResolve) {
            (self::$duringResolve)();
        }
        $resources = DB::table('p10_resources')->where('id', $resourceId);
        $memberships = DB::table('p10_memberships')->where('resource_id', $resourceId)->where('binding_hash', $scope->bindingHash)->where('actor', $scope->actorSubject);
        // Isolated host fixture's lock order: resource, then its membership, then package source fence.
        $resource = ($forUpdate ? $resources->lockForUpdate() : $resources)->first();
        $membership = ($forUpdate ? $memberships->lockForUpdate() : $memberships)->first();
        if (! $resource || ! $membership) {
            return null;
        }

        return new ApplicationContextResource($resourceId, $resource->label, $resource->version.':'.$membership->version, CarbonImmutable::now()->addMinutes(10));
    }
}

class CaseFixture implements ApplicationContextProvider
{
    public function choices(ApplicationContextScope $scope): iterable
    {
        yield $this->resolve($scope, 'one', false);
    }

    public function resolve(ApplicationContextScope $scope, string $resourceId, bool $forUpdate): ?ApplicationContextResource
    {
        return $resourceId === 'one' ? new ApplicationContextResource('one', 'Support case', 'v1', CarbonImmutable::now()->addMinute()) : null;
    }
}

class ScopedFixture implements ApplicationContextProvider
{
    public function __construct(private IdentityConfig $config) {}

    public function choices(ApplicationContextScope $scope): iterable
    {
        yield $this->resolve($scope, 'scoped', false);
    }

    public function resolve(ApplicationContextScope $scope, string $resourceId, bool $forUpdate): ?ApplicationContextResource
    {
        return new ApplicationContextResource($resourceId, $this->config->context()->name(), 'v1', CarbonImmutable::now()->addMinute());
    }
}
