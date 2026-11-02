<?php

namespace IdentityPlatform\Laravel\Tests\Authorization;

use Closure;
use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner;
use IdentityPlatform\Laravel\Authorization\Principal;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Profiles\LocalProfile;
use IdentityPlatform\Laravel\Profiles\LocalProfileManager;
use IdentityPlatform\Laravel\Profiles\LocalProfileRepository;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

class OrdinaryActionRunnerTest extends TestCase
{
    private Request $request;

    private IdentityUser $owner;

    private IdentitySession $session;

    private int $snapshotCalls = 0;

    private ?Closure $duringAuthority = null;

    protected function setUp(): void
    {
        parent::setUp();
        $this->owner = app(UserSynchronizer::class)->sync(['sub' => 'ordinary-person', 'name' => 'Ordinary person']);
        $this->session = app(SessionRepository::class)->create(['id' => 'ordinary-ledger', 'user_id' => $this->owner->id, 'subject' => 'ordinary-person', 'sid' => 'ordinary-source',
            'token_vault' => app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:ordinary-ledger'),
            'selection' => ['selected' => true], 'context_version' => 2, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $this->request = Request::create('https://consumer.test/account/profile', 'POST', ['context_version' => 2]);
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        $store->put('identity.session', $this->session->id);
        $this->request->setLaravelSession($store);
        $this->bindRequest($this->request);
        Http::preventStrayRequests();
        Http::fake(function ($request) {
            if ($request->url() !== 'https://identity.test/api/authorization/snapshot') {
                return null;
            }
            $this->snapshotCalls++;
            if ($this->duringAuthority) {
                ($this->duringAuthority)();
            }

            return Http::response(['contract' => 'platform-authorization-snapshot.v1', 'issuer' => 'https://identity.test/api/auth', 'subject' => 'ordinary-person',
                'central_session_id' => 'ordinary-source', 'application_id' => 'app-1', 'client_id' => 'web-1', 'principal_kind' => 'user', 'session_status' => 'active',
                'security_version' => 1, 'identity_status' => 'active', 'application_status' => 'active', 'grant_status' => 'active', 'organization_id' => null,
                'selected_role_id' => null, 'client_policy_version' => 1, 'role_ids' => [], 'roles' => [], 'permissions' => ['documents.update'],
                'authz_version' => 1, 'application_policy_version' => 1, 'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59),
                'assurance' => null, 'delegation' => null]);
        });
    }

    public function test_ordinary_profile_mutation_rolls_back_when_mode_changes_after_fresh_owner_check(): void
    {
        $profile = app(LocalProfileRepository::class)->read($this->owner);
        $repository = new class(app(IdentityConfig::class)) extends LocalProfileRepository
        {
            public function update(Authenticatable $owner, int $expectedVersion, array $fields): LocalProfile
            {
                IdentitySession::query()->whereKey('ordinary-ledger')->increment('context_version');

                return parent::update($owner, $expectedVersion, $fields);
            }
        };
        $this->graph()->instance(LocalProfileRepository::class, $repository);
        try {
            app(LocalProfileManager::class)->update($this->owner, 1, ['display_name' => 'Stale ordinary write']);
            $this->fail('Ordinary profile write committed behind a context fence');
        } catch (IdentityException $error) {
            $this->assertSame('context_changed', $error->errorCode);
        }
        $this->assertNull($profile->refresh()->display_name);
        $this->assertSame(1, $profile->version);
    }

    public function test_ordinary_runner_rechecks_context_after_resource_wait_before_mutation(): void
    {
        $this->assertTrue(class_exists(OrdinaryActionRunner::class), 'Ordinary transaction runner is missing');
        $profile = app(LocalProfileRepository::class)->read($this->owner);
        $mutated = false;
        try {
            app(OrdinaryActionRunner::class)->run($this->request, function () use ($profile) {
                IdentitySession::query()->whereKey('ordinary-ledger')->increment('context_version');

                return $profile;
            }, function () use (&$mutated): void {
                $mutated = true;
            });
            $this->fail('Stale ordinary action was accepted');
        } catch (IdentityException $error) {
            $this->assertSame('context_changed', $error->errorCode);
        }
        $this->assertFalse($mutated);
    }

    public function test_ordinary_runner_refuses_mode_started_during_authority_check(): void
    {
        $this->assertTrue(class_exists(OrdinaryActionRunner::class), 'Ordinary transaction runner is missing');
        $this->duringAuthority = function (): void {
            app(OverlayRepository::class)->save('ordinary-ledger', ['source_sid' => 'ordinary-source', 'status' => 'pending', 'browser_binding' => str_repeat('b', 43),
                'context_version' => 2, 'decision' => ['subject' => ['id' => 'subject-person']], 'expires_at' => now()->addMinute()]);
        };
        $this->expectExceptionObject(new IdentityException('ordinary_action_required', 403));
        app(OrdinaryActionRunner::class)->run($this->request, fn () => null, fn () => $this->fail('Delegated overlay entered ordinary mutation'));
    }

    public function test_ordinary_runner_holds_fence_and_exposes_only_fresh_ordinary_principal_to_mutation(): void
    {
        $this->assertTrue(class_exists(OrdinaryActionRunner::class), 'Ordinary transaction runner is missing');
        $rows = new class(app(IdentityConfig::class)) extends SessionRepository
        {
            public bool $locked = false;

            public function find(?string $id, bool $lock = false): ?IdentitySession
            {
                $this->locked = $this->locked || ($lock && (new IdentitySession)->getConnection()->transactionLevel() > 0);

                return parent::find($id, $lock);
            }
        };
        $this->graph()->instance(SessionRepository::class, $rows);
        $profile = app(LocalProfileRepository::class)->read($this->owner);
        $result = app(OrdinaryActionRunner::class)->run($this->request, fn () => $profile, function ($resource, Principal $principal) use ($rows): array {
            $this->assertTrue($rows->locked);
            $this->assertSame('ordinary-person', $principal->subject());
            $this->assertNull($principal->decision['delegation']);
            $this->assertTrue($principal->hasPermission('documents.update'));
            app(IdentityAccess::class)->assertOwner($this->owner);

            return ['version' => app(LocalProfileRepository::class)->update($this->owner, 1, ['display_name' => 'Fresh ordinary write'])->version];
        });
        $this->assertSame(['version' => 2], $result);
        $this->assertSame(1, $this->snapshotCalls);
    }

    public static function changedFences(): array
    {
        return [
            'source SID' => [['sid' => 'replacement-source']],
            'actor subject' => [['subject' => 'another-person']],
            'native projection' => [['user_id' => '00000000-0000-4000-a000-000000000001']],
            'token generation' => [['token_generation' => 2]],
            'selected context' => [['selection' => ['selected' => true, 'organizationId' => 'foreign-org']]],
            'fixed expiry' => [['expires_at' => '2000-01-01 00:00:00']],
            'absolute expiry' => [['started_at' => '2000-01-01 00:00:00']],
            'idle expiry' => [['last_activity_at' => '2000-01-01 00:00:00']],
        ];
    }

    #[DataProvider('changedFences')]
    public function test_ordinary_resource_wait_rechecks_source_generation_selection_and_deadlines(array $change): void
    {
        $mutated = false;
        try {
            app(OrdinaryActionRunner::class)->run($this->request, function () use ($change) {
                IdentitySession::query()->findOrFail('ordinary-ledger')->update($change);

                return null;
            }, function () use (&$mutated): void {
                $mutated = true;
            });
            $this->fail('Changed fence admitted an ordinary mutation');
        } catch (IdentityException $error) {
            $this->assertSame('context_changed', $error->errorCode);
        }
        $this->assertFalse($mutated);
    }

    public function test_owner_profile_service_retains_native_owner_authorization_inside_fence_transaction(): void
    {
        $other = app(UserSynchronizer::class)->sync(['sub' => 'another-person']);
        $profile = app(LocalProfileRepository::class)->read($other);
        try {
            app(LocalProfileManager::class)->update($other, 1, ['display_name' => 'Foreign edit']);
            $this->fail('Foreign native owner inherited current user authority');
        } catch (IdentityException $error) {
            $this->assertSame('access_denied', $error->errorCode);
        }
        $this->assertNull($profile->refresh()->display_name);
        $this->assertSame(1, $this->snapshotCalls);
    }

    public function test_general_ordinary_runner_rolls_back_deletion_of_its_authorizing_session(): void
    {
        try {
            app(OrdinaryActionRunner::class)->run($this->request, fn () => null, fn () => IdentitySession::query()->whereKey('ordinary-ledger')->delete());
            $this->fail('General ordinary mutation removed its own authorizing fence');
        } catch (IdentityException $error) {
            $this->assertSame('context_changed', $error->errorCode);
        }
        $this->assertDatabaseHas('identity_sessions', ['id' => 'ordinary-ledger']);
    }
}
