<?php

namespace IdentityPlatform\Laravel\Tests\Auth;

use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Delegation\DelegationManager;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Http\Middleware\DelegationBoundary;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Session\DatabaseSessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class SessionPersistenceUser extends User
{
    protected $table = 'session_native_users';

    protected $guarded = [];
}

class NativeGuardSessionPersistenceTest extends TestCase
{
    private Request $browser;

    private Store $store;

    protected function setUp(): void
    {
        parent::setUp();
        $this->configure(['auth.defaults.guard' => 'identity', 'auth.guards.identity' => ['driver' => 'identity'], 'identity.consumers.one.users.model' => SessionPersistenceUser::class, 'identity.consumers.one.users.fields' => ['name' => 'name', 'email' => 'email'],
            'identity.consumers.one.delegation.operations' => ['documents.read' => ['write' => false, 'resource_type' => 'document']]]);
        Schema::create('session_native_users', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->timestamps();
        });
        Schema::create('sessions', function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('user_id')->nullable();
            $table->string('ip_address')->nullable();
            $table->text('user_agent')->nullable();
            $table->text('payload');
            $table->integer('last_activity');
        });
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'operator-person', 'name' => 'Operator', 'email' => 'operator@example.test']);
        app(SessionRepository::class)->create(['id' => 'operator-ledger', 'user_id' => $projection->id, 'subject' => $projection->subject, 'sid' => 'operator-source',
            'token_vault' => app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:operator-ledger'),
            'selection' => ['selected' => true], 'context_version' => 2, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $this->store = new Store('consumer_session', new DatabaseSessionHandler(DB::connection(), 'sessions', 120, $this->app));
        $this->store->start();
        $this->store->put('identity.session', 'operator-ledger');
        $this->browser = Request::create('https://consumer.test/auth/delegation/start', 'POST', ['context_version' => 2]);
        $this->browser->setLaravelSession($this->store);
        $this->bindRequest($this->browser);
        $this->graph()->instance(ConsumerClient::class, new class extends ConsumerClient
        {
            public function __construct(private string $fixture = 'handoff-fixture') {}

            public function call(Request $request, string $operation, array $input = []): array
            {
                return ['handoffId' => $this->fixture, 'code' => str_repeat('c', 43), 'state' => $input['state'], 'callbackUrl' => $input['callbackUrl'], 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 60)];
            }
        });
    }

    private function startPendingMode(): void
    {
        $this->assertInstanceOf(SessionPersistenceUser::class, Auth::user());
        $destination = app(DelegationManager::class)->start($this->browser, ['subjectId' => 'target-person', 'operations' => ['documents.read'],
            'reason' => 'Investigate support case', 'ticketReference' => 'CASE-1', 'expectedPolicyVersion' => 1, 'expectedAuthorityVersion' => 1]);
        $this->assertSame('/auth/delegation/callback', parse_url($destination, PHP_URL_PATH));
        $this->assertSame('pending', app(OverlayRepository::class)->find('operator-ledger')->status);
        $this->assertSame(3, app(SessionRepository::class)->find('operator-ledger')->context_version);
    }

    public function test_database_session_save_after_valid_handoff_records_no_user_without_breaking_redirect(): void
    {
        $this->startPendingMode();
        $this->assertTrue($this->app->bound(Guard::class));
        try {
            $this->store->save();
        } catch (IdentityException $error) {
            $this->fail('Database session save must survive pending authority: '.$error->errorCode);
        }
        $this->assertDatabaseHas('sessions', ['id' => $this->store->getId(), 'user_id' => null]);
        $this->assertNull(Auth::id());
        $this->assertNull(Auth::user());
        $this->expectExceptionObject(new IdentityException('delegation_check_required', 403));
        app(IdentityAccess::class)->user();
    }

    public function test_pending_native_guard_is_anonymous_but_boundary_still_denies_protected_request(): void
    {
        $this->startPendingMode();
        try {
            $user = Auth::user();
        } catch (IdentityException $error) {
            $this->fail('General native guard must fail closed anonymously: '.$error->errorCode);
        }
        $this->assertNull($user);
        $this->assertInstanceOf(SessionPersistenceUser::class, app(IdentityAccess::class)->actor());
        $this->expectExceptionObject(new IdentityException('delegation_route_forbidden', 403));
        app(DelegationBoundary::class)->handle($this->browser, fn () => response('unsafe'));
    }

    public function test_guard_does_not_suppress_other_native_resolution_failures(): void
    {
        $access = $this->createStub(IdentityAccess::class);
        $access->method('user')->willThrowException(new IdentityException('identity_user_conflict', 409));
        $this->graph()->instance(IdentityAccess::class, $access);
        $this->expectExceptionObject(new IdentityException('identity_user_conflict', 409));
        Auth::user();
    }
}
