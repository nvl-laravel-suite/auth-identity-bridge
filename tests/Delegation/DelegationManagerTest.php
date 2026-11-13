<?php

namespace IdentityPlatform\Laravel\Tests\Delegation;

use Closure;
use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Delegation\DelegatedActionRepository;
use IdentityPlatform\Laravel\Delegation\DelegatedActionRunner;
use IdentityPlatform\Laravel\Delegation\DelegationManager;
use IdentityPlatform\Laravel\Delegation\IdentityDelegatedAction;
use IdentityPlatform\Laravel\Delegation\IdentityDelegation;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Delegation\ReportDelegatedAction;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Http\Middleware\DelegationBoundary;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Services\ServiceTokenManager;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Queue\Events\JobQueueing;
use Illuminate\Routing\Route;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Schema;

class FakeDelegationClient extends ConsumerClient
{
    public array $calls = [];

    public function __construct(public Closure $handler) {}

    public function call(Request $request, string $operation, array $input = []): array
    {
        $this->calls[] = [$operation, $input];

        return ($this->handler)($request, $operation, $input);
    }
}

class DelegationManagerTest extends TestCase
{
    protected IdentitySession $ledger;

    protected Request $browser;

    protected FakeDelegationClient $client;

    private ?array $modeFacts = null;

    protected function setUp(): void
    {
        parent::setUp();
        $this->assertTrue(class_exists(DelegationManager::class), 'Delegation manager is missing');
        $actor = app(UserSynchronizer::class)->sync(['sub' => 'operator-1', 'name' => 'Operator', 'email' => 'operator@example.test']);
        $this->ledger = IdentitySession::query()->create(['id' => 'ledger-1', 'binding_hash' => app(IdentityConfig::class)->bindingHash(), 'user_id' => $actor->id, 'subject' => 'operator-1', 'sid' => 'sid-1',
            'token_vault' => app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:ledger-1'),
            'selection' => ['selected' => true], 'context_version' => 2, 'token_generation' => 1,
            'snapshot' => null, 'started_at' => now()->subMinutes(10), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $this->browser = Request::create('https://consumer.test/delegation', 'POST', ['context_version' => 2]);
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        $store->put('identity.session', $this->ledger->id);
        $this->browser->setLaravelSession($store);
        $this->bindRequest($this->browser);
        $this->client = new FakeDelegationClient(function (Request $request, string $operation, array $input): array {
            return match ($operation) {
                'delegation.start' => ['handoffId' => 'handoff-1', 'code' => str_repeat('c', 43), 'state' => $input['state'], 'callbackUrl' => $input['callbackUrl'], 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 60)],
                'delegation.redeem' => ['handle' => str_repeat('h', 43), 'decision' => $this->decision()],
                'delegation.check' => $this->decision(),
                'delegation.stop' => ['stopped' => true],
                default => throw new \RuntimeException('Unexpected fake operation'),
            };
        });
        $this->configure(['identity.consumers.one.delegation.routes' => ['documents.show' => 'documents.read', 'documents.update' => 'documents.update'],
            'identity.consumers.one.delegation.operations' => ['documents.read' => ['write' => false, 'resource_type' => 'documents'], 'documents.update' => ['write' => true, 'resource_type' => 'documents']]]);
        $this->graph()->instance(ConsumerClient::class, $this->client);
    }

    protected function input(): array
    {
        return ['subjectId' => 'subject-1', 'operations' => ['documents.read', 'documents.update'], 'reason' => 'Investigate support case', 'ticketReference' => 'CASE-1', 'expectedPolicyVersion' => 1, 'expectedAuthorityVersion' => 1];
    }

    protected function decision(): array
    {
        $data = ['contract' => 'platform-consumer-delegation.v1', 'issuer' => 'https://identity.test/api/auth', 'delegationId' => 'mode-1',
            'actor' => ['id' => 'operator-1', 'name' => 'Operator', 'email' => 'operator@example.test', 'sourceSessionId' => 'sid-1', 'assurance' => ['centralSessionId' => 'sid-1', 'verifiedAt' => gmdate('Y-m-d\TH:i:s\Z')]],
            'subject' => ['id' => 'subject-1', 'name' => 'Subject', 'email' => 'subject@example.test', 'locale' => 'en', 'classification' => 'person', 'assurance' => null],
            'applicationId' => 'app-1', 'clientId' => 'web-1', 'organizationId' => null, 'roleId' => null, 'actorRoleId' => null, 'contextVersion' => 3,
            'operations' => ['documents.read', 'documents.update'], 'permissions' => ['documents.read', 'documents.update'], 'versions' => ['authority' => 1], 'reason' => 'Investigate support case', 'ticketReference' => 'CASE-1',
            'startedAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 1), 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 300), 'checkedAt' => gmdate('Y-m-d\TH:i:s\Z'), 'decisionValidUntil' => gmdate('Y-m-d\TH:i:s\Z', time() + 4)];
        $this->modeFacts ??= $data;

        return [...$this->modeFacts, 'checkedAt' => $data['checkedAt'], 'decisionValidUntil' => $data['decisionValidUntil']];
    }

    protected function activate(): DelegationManager
    {
        $manager = app(DelegationManager::class);
        $url = $manager->start($this->browser, $this->input());
        parse_str(parse_url($url, PHP_URL_QUERY), $callback);
        $this->browser->setMethod('GET');
        $this->browser->request->replace([]);
        $manager->redeem($this->browser, $callback);

        return $manager;
    }

    public function test_start_and_redeem_keep_actor_ledger_and_bind_one_use_browser_handoff(): void
    {
        $started = $this->ledger->started_at->toIso8601String();
        $manager = $this->activate();
        $this->assertSame(3, $this->ledger->refresh()->context_version);
        $this->assertSame($started, $this->ledger->started_at->toIso8601String());
        $this->assertSame('operator-1', $this->ledger->subject);
        $overlay = $manager->current($this->browser);
        $this->assertSame('active', $overlay->status);
        $this->assertStringNotContainsString(str_repeat('h', 43), $overlay->handle_vault);
        $this->assertSame('sid-1', $overlay->source_sid);
        $this->assertSame('subject-1', $manager->check($this->browser, 'documents.read')->principal()->subject());
        $access = app(IdentityAccess::class);
        $this->assertSame('operator-1', $access->actor()->subject);
        $this->assertSame('subject-1', $access->user()->subject);
        $this->assertFalse($access->principal()->recentMfa());
    }

    public function test_pending_mode_denies_native_user_resolution_without_a_fresh_decision(): void
    {
        app(DelegationManager::class)->start($this->browser, $this->input());
        $this->expectException(IdentityException::class);
        app(IdentityAccess::class)->user();
    }

    public function test_boundary_denies_unknown_route_even_when_local_gate_would_allow(): void
    {
        $this->activate();
        $route = new Route('GET', '/admin', fn () => 'unsafe');
        $route->name('admin.users');
        $this->browser->setRouteResolver(fn () => $route);
        $this->expectExceptionObject(new IdentityException('delegation_route_forbidden', 403));
        app(DelegationBoundary::class)->handle($this->browser, fn () => response('unsafe'));
    }

    public function test_boundary_checks_each_protected_request_and_rejects_stale_write_form(): void
    {
        $this->activate();
        $route = new Route('POST', '/documents/1', fn () => 'unsafe');
        $route->name('documents.update');
        $this->browser->setRouteResolver(fn () => $route);
        $this->browser->setMethod('POST');
        $this->browser->request->set('context_version', 2);
        $this->expectExceptionObject(new IdentityException('context_changed', 409));
        app(DelegationBoundary::class)->handle($this->browser, fn () => response('unsafe'));
    }

    public function test_stop_clears_local_handle_and_fences_before_remote_outage(): void
    {
        $manager = $this->activate();
        $this->browser->setMethod('POST');
        $this->browser->request->set('context_version', 3);
        $this->client->handler = function (): array {
            $this->assertSame('stopped', IdentityDelegation::query()->find('ledger-1')->status);
            $this->assertSame(4, $this->ledger->refresh()->context_version);
            throw new IdentityException('identity_unavailable', 503);
        };
        $manager->stop($this->browser);
        $this->assertNull(app(OverlayRepository::class)->find('ledger-1'));
        $this->assertNull(IdentityDelegation::query()->find('ledger-1')->handle_vault);
        $this->assertNull(app(SessionManager::class)->current($this->browser));
    }

    protected function actions(?Closure $duringAdmission = null): DelegatedActionRunner
    {
        $this->assertTrue(class_exists(DelegatedActionRunner::class), 'Transactional action runner is missing');
        $this->activate();
        Queue::fake();
        Schema::create('owned_documents', function (Blueprint $table): void {
            $table->id();
            $table->string('title');
        });
        DB::table('owned_documents')->insert(['id' => 1, 'title' => 'Before']);
        $this->browser->setMethod('POST');
        $this->browser->request->set('context_version', 3);
        $this->client->handler = function (Request $request, string $operation, array $input) use ($duringAdmission): array {
            if ($operation === 'delegation.check') {
                return $this->decision();
            }
            if ($operation === 'delegation.admit') {
                $reply = ['receiptId' => 'receipt-1', 'delegationId' => 'mode-1', 'contextVersion' => 3, 'operation' => $input['operation'], 'organizationId' => null,
                    'resourceType' => $input['resourceType'], 'resourceId' => $input['resourceId'], 'commandDigest' => $input['commandDigest'], 'idempotencyKey' => $input['idempotencyKey'],
                    'admittedAt' => gmdate('Y-m-d\TH:i:s\Z'), 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 4), 'reportingCapability' => str_repeat('r', 43),
                    'reportingExpiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 600), 'decision' => $this->decision()];

                return $duringAdmission ? $duringAdmission($reply) : $reply;
            }

            throw new \RuntimeException('Unexpected fake operation');
        };

        return app(DelegatedActionRunner::class);
    }

    protected function runAction(DelegatedActionRunner $runner, ?Closure $lock = null, ?Closure $mutate = null, array $command = ['title' => 'After']): array
    {
        return $runner->run($this->browser, 'documents.update', 'documents', '1', $command, str_repeat('i', 43), $lock ?? fn () => DB::table('owned_documents')->where('id', 1)->lockForUpdate()->first(), $mutate ?? function ($resource): array {
            DB::table('owned_documents')->where('id', $resource->id)->update(['title' => 'After']);

            return ['title' => 'After'];
        });
    }

    public function test_refused_admission_keeps_its_reporting_capability_out_of_the_stack_trace(): void
    {
        $capability = 'synthetic-reporting-capability-that-must-not-be-traced';
        $runner = $this->actions(fn (array $reply): array => [...$reply, 'receiptId' => '', 'reportingCapability' => $capability]);
        $previous = ini_set('zend.exception_ignore_args', '0');
        try {
            $this->runAction($runner);
            $this->fail('An invalid admission receipt was accepted');
        } catch (IdentityException $error) {
            $this->assertSame('invalid_delegation_admission', $error->errorCode);
            $arguments = [];
            $trace = $error->getTrace();
            array_walk_recursive($trace, function (mixed $value) use (&$arguments): void {
                if (is_string($value)) {
                    $arguments[] = $value;
                }
            });
            $this->assertStringNotContainsString($capability, implode("\n", $arguments));
        } finally {
            ini_set('zend.exception_ignore_args', (string) $previous);
        }
    }

    public function test_delegated_mutation_audit_and_narrow_reporting_outbox_commit_together(): void
    {
        $runner = $this->actions();
        $result = $this->runAction($runner);
        $this->assertSame(['title' => 'After'], $result);
        $this->assertDatabaseHas('owned_documents', ['id' => 1, 'title' => 'After']);
        $action = IdentityDelegatedAction::query()->firstOrFail();
        $this->assertSame('committed', $action->outcome);
        $this->assertSame('operator-1', $action->actor_id);
        $this->assertSame('subject-1', $action->subject_id);
        $this->assertSame('1', $action->resource_id);
        $this->assertStringNotContainsString(str_repeat('r', 43), $action->receipt_vault);
        Queue::assertPushed(ReportDelegatedAction::class, fn ($job) => $job->actionId === $action->id);
        $this->assertStringNotContainsString('synthetic', serialize(new ReportDelegatedAction($action->id)));
        $this->assertSame($result, $this->runAction($runner));
        $this->assertDatabaseCount('identity_delegated_actions', 1);
    }

    public function test_boundary_and_runner_share_one_check_but_still_admit_the_mutation(): void
    {
        $runner = $this->actions();
        $route = new Route('POST', '/documents/1', fn () => 'unused');
        $route->name('documents.update');
        $this->browser->setRouteResolver(fn () => $route);
        app(DelegationBoundary::class)->handle($this->browser, function () use ($runner) {
            $this->assertSame(['title' => 'After'], $this->runAction($runner));

            return response('saved');
        });
        $operations = array_column($this->client->calls, 0);
        $this->assertSame(1, count(array_filter($operations, fn ($operation) => $operation === 'delegation.check')));
        $this->assertSame(1, count(array_filter($operations, fn ($operation) => $operation === 'delegation.admit')));
        $this->assertDatabaseHas('owned_documents', ['id' => 1, 'title' => 'After']);
        $this->assertDatabaseHas('identity_delegated_actions', ['outcome' => 'committed']);
    }

    public function test_conflicting_idempotency_cannot_repeat_a_local_mutation(): void
    {
        $runner = $this->actions();
        $this->runAction($runner);
        $this->expectExceptionObject(new IdentityException('delegation_idempotency_conflict', 409));
        $this->runAction($runner, command: ['title' => 'Different']);
    }

    public function test_context_change_while_waiting_for_resource_lock_prevents_mutation(): void
    {
        $runner = $this->actions();
        try {
            $this->runAction($runner, function () {
                IdentitySession::query()->whereKey('ledger-1')->update(['context_version' => 4]);

                return DB::table('owned_documents')->where('id', 1)->first();
            });
            $this->fail('Changed context admitted a write');
        } catch (IdentityException $error) {
            $this->assertSame('context_changed', $error->errorCode);
        }
        $this->assertDatabaseHas('owned_documents', ['id' => 1, 'title' => 'Before']);
        $this->assertDatabaseHas('identity_delegated_actions', ['outcome' => 'rejected']);
    }

    public function test_failed_domain_mutation_rolls_back_and_records_only_rejected_outcome(): void
    {
        $runner = $this->actions();
        try {
            $this->runAction($runner, mutate: function ($resource): array {
                DB::table('owned_documents')->where('id', $resource->id)->update(['title' => 'Partial']);
                throw new \RuntimeException('private-domain-error');
            });
            $this->fail('Domain failure was hidden');
        } catch (\RuntimeException $error) {
            $this->assertSame('private-domain-error', $error->getMessage());
        }
        $this->assertDatabaseHas('owned_documents', ['id' => 1, 'title' => 'Before']);
        $action = IdentityDelegatedAction::query()->firstOrFail();
        $this->assertSame('rejected', $action->outcome);
        $this->assertStringNotContainsString('private-domain-error', json_encode($action->toArray()));
    }

    public function test_receipt_expiring_while_waiting_for_resource_lock_prevents_mutation(): void
    {
        $runner = $this->actions(function (array $receipt): array {
            $now = microtime(true);
            $admittedAt = \DateTimeImmutable::createFromFormat('U.u', sprintf('%.6F', $now))
                ->setTimezone(new \DateTimeZone('UTC'))
                ->format('Y-m-d\TH:i:s.u\Z');
            $expiresAt = \DateTimeImmutable::createFromFormat('U.u', sprintf('%.6F', $now + 0.12))
                ->setTimezone(new \DateTimeZone('UTC'))
                ->format('Y-m-d\TH:i:s.u\Z');

            return [...$receipt, 'admittedAt' => $admittedAt, 'expiresAt' => $expiresAt];
        });
        try {
            $this->runAction($runner, function () {
                usleep(150000);

                return DB::table('owned_documents')->where('id', 1)->first();
            });
            $this->fail('Expired admission mutated domain state');
        } catch (IdentityException $error) {
            $this->assertSame('delegation_admission_expired', $error->errorCode);
        }
        $this->assertDatabaseHas('owned_documents', ['id' => 1, 'title' => 'Before']);
    }

    public function test_reporting_job_only_uses_receipt_capability_after_actor_and_overlay_are_revoked(): void
    {
        $runner = $this->actions();
        $this->runAction($runner);
        $action = IdentityDelegatedAction::query()->firstOrFail();
        IdentitySession::query()->delete();
        app(OverlayRepository::class)->stop('ledger-1');
        Http::fake(['https://identity.test/api/consumer/v1/delegations/complete-operation' => Http::response(['contract' => 'platform-consumer-outcome.v1', 'issuer' => 'https://identity.test/api/auth', 'clientId' => 'web-1', 'data' => ['receiptId' => 'receipt-1', 'status' => 'committed']])]);
        $this->app->forgetInstance(ConsumerGraph::class);
        $this->app->call([new ReportDelegatedAction($action->id), 'handle']);
        Http::assertSent(fn ($request) => $request['input']['receiptId'] === 'receipt-1' && $request['input']['outcome'] === 'committed' && isset($request['input']['reportingCapability']));
        $this->assertNotNull($action->refresh()->reported_at);
    }

    public function test_actual_web_pipeline_denies_unregistered_route_before_any_local_superuser_gate(): void
    {
        $this->activate();
        Gate::before(fn () => true);
        \Illuminate\Support\Facades\Route::middleware('web')->get('/unregistered-admin', function () {
            Gate::authorize('admin.update');

            return 'unsafe';
        })->name('admin.update');
        $this->withSession(['identity.session' => 'ledger-1'])->get('/unregistered-admin')->assertStatus(403)->assertExactJson(['error' => 'delegation_route_forbidden']);
    }

    public function test_browser_handoff_state_cannot_be_replayed_or_consumed_from_another_browser(): void
    {
        $manager = app(DelegationManager::class);
        $url = $manager->start($this->browser, $this->input());
        parse_str(parse_url($url, PHP_URL_QUERY), $callback);
        $foreign = Request::create('https://consumer.test/auth/delegation/callback');
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        $store->put('identity.session', 'ledger-1');
        $foreign->setLaravelSession($store);
        try {
            $manager->redeem($foreign, $callback);
            $this->fail('Foreign browser consumed handoff');
        } catch (IdentityException $error) {
            $this->assertSame('invalid_login_state', $error->errorCode);
        }
        $this->browser->setMethod('GET');
        $manager->redeem($this->browser, $callback);
        $this->expectExceptionObject(new IdentityException('invalid_login_state', 401));
        $manager->redeem($this->browser, $callback);
    }

    public function test_activity_query_is_scoped_to_bound_person_and_omits_proofs_and_digests(): void
    {
        $runner = $this->actions();
        $this->runAction($runner);
        $repository = app(DelegatedActionRepository::class);
        $this->assertTrue(method_exists($repository, 'forPerson'), 'Safe person activity query is missing');
        $action = IdentityDelegatedAction::query()->firstOrFail();
        $other = $action->replicate();
        $other->id = 'another-action';
        $other->actor_id = 'foreign-actor';
        $other->subject_id = 'foreign-subject';
        $other->save();
        $foreign = $action->replicate();
        $foreign->id = 'foreign-binding-action';
        $foreign->binding_hash = str_repeat('f', 64);
        $foreign->save();
        $entries = $repository->forPerson('subject-1');
        $this->assertCount(1, $entries);
        $this->assertSame('committed', $entries[0]['outcome']);
        $this->assertArrayNotHasKey('receipt_vault', $entries[0]);
        $this->assertArrayNotHasKey('command_digest', $entries[0]);
        $this->assertArrayNotHasKey('session_id', $entries[0]);
        $this->assertStringNotContainsString(str_repeat('r', 43), json_encode($entries));
    }

    public function test_delegated_browser_cannot_queue_unknown_work_as_ambient_authority(): void
    {
        $this->activate();
        $this->expectExceptionObject(new IdentityException('delegation_queue_forbidden', 403));
        event(new JobQueueing('database', 'default', new \stdClass, '{}', null));
    }

    public function test_delegated_browser_cannot_acquire_machine_credentials_for_outbound_work(): void
    {
        $this->activate();
        $this->expectExceptionObject(new IdentityException('delegation_outbound_forbidden', 403));
        app(ServiceTokenManager::class)->target('reports')->token(['documents.read']);
    }

    public function test_operator_assurance_expiring_while_waiting_for_resource_lock_prevents_mutation(): void
    {
        $runner = $this->actions(function (array $receipt): array {
            $receipt['decision']['actor']['assurance']['verifiedAt'] = \DateTimeImmutable::createFromFormat('U.u', sprintf('%.6F', microtime(true) - 299.88))
                ->setTimezone(new \DateTimeZone('UTC'))
                ->format('Y-m-d\TH:i:s.u\Z');

            return $receipt;
        });
        try {
            $this->runAction($runner, function () {
                usleep(150000);

                return DB::table('owned_documents')->where('id', 1)->first();
            });
            $this->fail('Expired operator assurance mutated domain state');
        } catch (IdentityException $error) {
            $this->assertSame('delegation_admission_expired', $error->errorCode);
        }
        $this->assertDatabaseHas('owned_documents', ['id' => 1, 'title' => 'Before']);
    }

    public function test_invalidated_mode_can_still_be_locally_retired_using_its_own_stop_form(): void
    {
        $manager = $this->activate();
        IdentitySession::query()->whereKey('ledger-1')->increment('context_version');
        $this->browser->setMethod('POST');
        $this->browser->request->set('context_version', 3);
        $manager->stop($this->browser);
        $this->assertNull(app(OverlayRepository::class)->find('ledger-1'));
    }

    public function test_mutation_holds_the_native_session_fence_lock_inside_the_domain_transaction(): void
    {
        $repository = new class(app(IdentityConfig::class)) extends SessionRepository
        {
            public bool $lockedInsideTransaction = false;

            public function find(?string $id, bool $lock = false): ?IdentitySession
            {
                if ($lock && (new IdentitySession)->getConnection()->transactionLevel() > 0) {
                    $this->lockedInsideTransaction = true;
                }

                return parent::find($id, $lock);
            }
        };
        $this->graph()->instance(SessionRepository::class, $repository);
        $runner = $this->actions();
        $repository->lockedInsideTransaction = false;
        $this->runAction($runner, mutate: function ($resource) use ($repository): array {
            $this->assertTrue($repository->lockedInsideTransaction, 'Domain mutation must hold the session fence row lock');
            DB::table('owned_documents')->where('id', $resource->id)->update(['title' => 'After']);

            return ['title' => 'After'];
        });
    }

    public function test_fresh_mode_check_replaces_an_ordinary_user_cached_by_the_native_guard(): void
    {
        $this->configure(['auth.guards.identity' => ['driver' => 'identity'], 'auth.defaults.guard' => 'identity']);
        $operator = app(IdentityAccess::class)->actor();
        $manager = $this->activate();
        Auth::guard('identity')->setUser($operator);
        $this->assertSame('operator-1', Auth::user()->subject);
        $manager->check($this->browser, 'documents.read');
        $this->assertSame('subject-1', Auth::user()->subject);
        $this->assertSame('operator-1', app(IdentityAccess::class)->actor()->subject);
    }

    public function test_admission_budget_counts_client_wait_before_a_new_response_timestamp(): void
    {
        $runner = $this->actions(function (array $receipt): array {
            usleep(150000);
            $issued = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
            $receipt['admittedAt'] = $issued->format('Y-m-d\TH:i:s.u\Z');
            $receipt['expiresAt'] = $issued->modify('+100 milliseconds')->format('Y-m-d\TH:i:s.u\Z');

            return $receipt;
        });
        try {
            $this->runAction($runner);
            $this->fail('Client wait extended the provider receipt duration');
        } catch (IdentityException $error) {
            $this->assertSame('delegation_admission_expired', $error->errorCode);
        }
        $this->assertDatabaseHas('owned_documents', ['id' => 1, 'title' => 'Before']);
    }
}
