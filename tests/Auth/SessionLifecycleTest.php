<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Auth;

use Closure;
use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Http\Middleware\Permission;
use IdentityPlatform\Laravel\Http\Middleware\RecentMfa;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\ProfileSynchronized;
use IdentityPlatform\Laravel\Tests\Oidc\ProviderFixture;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;

class SessionLifecycleTest extends TestCase
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

    public function test_real_oidc_completion_requires_live_contexts_before_any_local_projection_or_session(): void
    {
        $this->choices = [];
        $request = $this->browser();
        $manager = app(SessionManager::class);
        $callback = $this->start($manager, $request);
        try {
            $manager->complete($request, $callback);
            $this->fail('Ineligible identity gained local session');
        } catch (IdentityException $error) {
            $this->assertSame('access_denied', $error->errorCode);
            $this->assertSame(0, IdentitySession::query()->count());
            $this->assertSame(0, IdentityUser::query()->count());
            $this->assertNull($request->session()->get('identity.session'));
        }
    }

    public function test_login_intent_expires_after_the_last_network_wait_before_publication(): void
    {
        $this->duringContexts = fn () => $this->travel(301)->seconds();
        $request = $this->browser();
        $manager = app(SessionManager::class);
        try {
            $manager->complete($request, $this->start($manager, $request));
            $this->fail('Expired continuation published a session');
        } catch (IdentityException $error) {
            $this->assertSame('login_expired', $error->errorCode);
            $this->assertSame(0, IdentitySession::query()->count());
            $this->assertSame(0, IdentityUser::query()->count());
        }
    }

    public function test_complete_select_and_cached_read_keep_tokens_server_side_and_reject_state_reuse(): void
    {
        $request = $this->browser();
        $manager = app(SessionManager::class);
        $before = $request->session()->getId();
        $callback = $this->start($manager, $request);
        $manager->complete($request, $callback);
        $this->assertNotSame($before, $request->session()->getId());
        $this->assertSame(1, $this->contextsCalls);
        $manager->select($request, [], 1);
        $this->assertTrue($manager->principal($request)->hasPermission('documents.read'));
        $this->assertTrue($manager->principal($request)->hasPermission('documents.read'));
        $this->assertSame(1, $this->snapshotCalls);
        $this->assertSame(2, $this->row($request)->context_version);
        $this->assertStringNotContainsString('synthetic-access-token', json_encode($request->session()->all(), JSON_THROW_ON_ERROR));
        $this->assertStringNotContainsString('synthetic-access-token', $this->row($request)->token_vault);
        $this->expectException(IdentityException::class);
        $manager->complete($request, $callback);
    }

    public function test_snapshot_return_cannot_publish_over_concurrent_invalidation(): void
    {
        $request = $this->browser();
        $manager = $this->login($request);
        $manager->select($request, [], 1);
        $this->duringSnapshot = function () use ($request): void {
            IdentitySession::query()->whereKey($this->row($request)->id)->update(['context_version' => 3, 'snapshot' => null]);
        };
        try {
            $manager->principal($request, true);
            $this->fail('Stale authorization result published');
        } catch (IdentityException $error) {
            $this->assertSame('context_changed', $error->errorCode);
            $this->assertNull($this->row($request)->snapshot);
            $this->assertSame(3, $this->row($request)->context_version);
        }
    }

    public function test_cached_principal_rechecks_session_version_after_activity_publication(): void
    {
        $request = $this->browser();
        $manager = $this->login($request);
        $manager->select($request, [], 1);
        $invalidate = true;
        DB::listen(function (QueryExecuted $query) use (&$invalidate, $request): void {
            if ($invalidate && str_starts_with($query->sql, 'update "identity_sessions"') && str_contains($query->sql, 'last_activity_at')) {
                $invalidate = false;
                IdentitySession::query()->whereKey($this->row($request)->id)->update(['context_version' => 3, 'snapshot' => null]);
            }
        });
        $this->expectExceptionObject(new IdentityException('context_changed', 409));
        $manager->principal($request);
    }

    public function test_refresh_replaces_once_preserves_original_deadlines_and_never_resurrects_deleted_row(): void
    {
        $request = $this->browser();
        $manager = $this->login($request);
        $row = $this->row($request);
        $before = [$row->started_at->format('c'), $row->expires_at->format('c')];
        $vault = app(IdentityVault::class);
        $tokens = $vault->open($row->token_vault, 'session:'.$row->id);
        $tokens['expires_at'] = time() - 1;
        $row->update(['token_vault' => $vault->seal($tokens, 'session:'.$row->id)]);
        $refreshed = $manager->current($request);
        $this->assertSame(2, $refreshed->token_generation);
        $this->assertSame($before, [$refreshed->started_at->format('c'), $refreshed->expires_at->format('c')]);
        $manager->current($request);
        $this->assertCount(2, $this->provider->tokenForms());
        $next = $vault->open($refreshed->token_vault, 'session:'.$row->id);
        $next['expires_at'] = time() - 1;
        $refreshed->update(['token_vault' => $vault->seal($next, 'session:'.$row->id)]);
        $this->duringToken = fn () => IdentitySession::query()->whereKey($row->id)->delete();
        try {
            $manager->current($request);
            $this->fail('Deleted local session was resurrected');
        } catch (IdentityException $error) {
            $this->assertSame('session_changed', $error->errorCode);
            $this->assertSame(0, IdentitySession::query()->count());
        }
    }

    public function test_refresh_publication_followed_by_deletion_clears_the_browser_pointer(): void
    {
        $request = $this->browser();
        $manager = $this->login($request);
        $row = $this->row($request);
        $vault = app(IdentityVault::class);
        $tokens = $vault->open($row->token_vault, 'session:'.$row->id);
        $tokens['expires_at'] = time() - 1;
        $row->update(['token_vault' => $vault->seal($tokens, 'session:'.$row->id)]);
        DB::listen(function (QueryExecuted $query) use ($row): void {
            if (str_starts_with($query->sql, 'update "identity_sessions"') && str_contains($query->sql, 'token_generation')) {
                IdentitySession::whereKey($row->id)->delete();
            }
        });

        $this->assertNull($manager->current($request));
        $this->assertNull($request->session()->get('identity.session'));
        $this->assertDatabaseCount('identity_sessions', 0);
    }

    public function test_refresh_result_is_not_published_after_refresh_lease_expires(): void
    {
        $request = $this->browser();
        $manager = $this->login($request);
        $row = $this->row($request);
        $vault = app(IdentityVault::class);
        $tokens = $vault->open($row->token_vault, 'session:'.$row->id);
        $tokens['expires_at'] = time() - 1;
        $row->update(['token_vault' => $vault->seal($tokens, 'session:'.$row->id)]);
        $this->duringToken = fn () => $this->travel(61)->seconds();
        try {
            $manager->current($request);
            $this->fail('Lost refresh lease published tokens');
        } catch (IdentityException $error) {
            $this->assertSame('session_busy', $error->errorCode);
            $this->assertSame(1, $row->fresh()->token_generation);
        }
    }

    public function test_profile_hook_cannot_publish_refreshed_tokens_after_lease_expires(): void
    {
        $request = $this->browser();
        $manager = $this->login($request);
        $row = $this->row($request);
        $vault = app(IdentityVault::class);
        $tokens = $vault->open($row->token_vault, 'session:'.$row->id);
        $tokens['expires_at'] = time() - 1;
        $row->update(['token_vault' => $vault->seal($tokens, 'session:'.$row->id)]);
        Event::listen(ProfileSynchronized::class, fn () => $this->travel(61)->seconds());
        try {
            $manager->current($request);
            $this->fail('Expired lease published after application profile hook');
        } catch (IdentityException $error) {
            $this->assertSame('session_busy', $error->errorCode);
            $this->assertSame(1, $row->fresh()->token_generation);
        }
    }

    public function test_mfa_middleware_gets_fresh_authority_after_permission_used_cached_read_snapshot(): void
    {
        $request = $this->browser();
        $manager = $this->login($request);
        $manager->select($request, [], 1);
        $permission = app(Permission::class);
        $mfa = app(RecentMfa::class);
        $response = $permission->handle($request, fn ($request) => $mfa->handle($request, fn () => response('authorized')), 'documents.read');
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(2, $this->snapshotCalls);
    }

    public function test_local_logout_retires_local_authority_even_if_remote_revocation_cannot_complete(): void
    {
        $request = $this->browser();
        $manager = $this->login($request);
        $this->assertNull($manager->logout($request));
        $this->assertSame(0, IdentitySession::query()->count());
        $this->assertNull($request->session()->get('identity.session'));
        Http::assertSent(fn (HttpRequest $request) => $request->url() === ProviderFixture::ISSUER.'/oauth2/revoke');
        $this->assertNull($manager->current($request));
    }
}
