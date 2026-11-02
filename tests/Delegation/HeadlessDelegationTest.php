<?php

namespace IdentityPlatform\Laravel\Tests\Delegation;

use Closure;
use IdentityPlatform\Laravel\Auth\AuthStatePresenter;
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Delegation\DelegationManager;
use IdentityPlatform\Laravel\Delegation\IdentityDelegation;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Events\DelegationStateChanged;
use IdentityPlatform\Laravel\Events\LocalSessionEnded;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;

class HeadlessFakeDelegationClient extends ConsumerClient
{
    public array $calls = [];

    public function __construct(public Closure $handler) {}

    public function call(Request $request, string $operation, array $input = []): array
    {
        $this->calls[] = [$operation, $input];

        return ($this->handler)($request, $operation, $input);
    }
}

class HeadlessDelegationTest extends TestCase
{
    protected IdentitySession $ledger;

    protected Request $browser;

    protected HeadlessFakeDelegationClient $client;

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
        $this->client = new HeadlessFakeDelegationClient(function (Request $request, string $operation, array $input): array {
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

    public function test_delegation_events_follow_committed_pending_active_and_stop_states_despite_listener_failure(): void
    {
        $events = [];
        $observed = [];
        Event::listen(DelegationStateChanged::class, function ($event) use (&$events, &$observed): void {
            $events[] = $event;
            $observed[] = [IdentityDelegation::findOrFail('ledger-1')->status, IdentitySession::findOrFail('ledger-1')->context_version];
            throw new \RuntimeException('Optional notification failure');
        });
        $manager = $this->activate();
        self::assertCount(2, $events);
        self::assertSame(['pending', 'active'], array_column($events, 'status'));
        $manager->check($this->browser, 'documents.read');
        self::assertCount(2, $events);
        $this->browser->setMethod('POST');
        $this->browser->merge(['context_version' => 3]);
        Http::preventStrayRequests();
        Http::fake(fn () => Http::response([], 503));
        $manager->stop($this->browser);
        self::assertCount(3, $events);
        self::assertSame('stopped', $events[2]->status);
        self::assertSame([['pending', 3], ['active', 3], ['stopped', 4]], $observed);
        self::assertNull(app(OverlayRepository::class)->find('ledger-1'));
        self::assertNull(IdentityDelegation::findOrFail('ledger-1')->handle_vault);
        $json = json_encode($events, JSON_THROW_ON_ERROR);
        foreach (['handle', 'sid-1', 'CASE-1', 'Investigate', 'browser_binding', 'decision'] as $private) {
            self::assertStringNotContainsString($private, $json);
        }
    }

    public function test_state_distinguishes_actor_effective_subject_and_preserves_finite_delegated_permission_view(): void
    {
        self::assertTrue(class_exists(AuthStatePresenter::class), 'Safe public presenter is missing');
        $manager = $this->activate();
        $this->bindRequest($this->browser);
        $manager->check($this->browser, 'documents.read');
        $state = $this->graph()->make(AuthStatePresenter::class)->current();
        self::assertSame('operator-1', $state->actor?->subject);
        self::assertSame('subject-1', $state->effectiveSubject?->subject);
        self::assertSame('active', $state->delegationStatus);
        self::assertNotNull($state->delegationExpiresAt);
        self::assertNull($state->decision->selectedRole);
        self::assertSame(['documents.read', 'documents.update'], $state->decision->permissions);
        foreach (['CASE-1', 'Investigate', 'handle', 'sid-1', 'assurance'] as $private) {
            self::assertStringNotContainsString($private, json_encode($state));
        }
        $this->browser->attributes->remove('identity.delegation');
        self::assertNull($this->graph()->make(AuthStatePresenter::class)->current()->actor);
    }

    public function test_failed_redeem_and_replay_do_not_emit_active_notification(): void
    {
        Event::fake([DelegationStateChanged::class]);
        $manager = app(DelegationManager::class);
        parse_str(parse_url($manager->start($this->browser, $this->input()), PHP_URL_QUERY), $callback);
        $this->client->handler = fn () => throw new IdentityException('provider_unavailable', 503);
        try {
            $manager->redeem($this->browser, $callback);
            self::fail('Failed redeem accepted');
        } catch (IdentityException $error) {
            self::assertSame('provider_unavailable', $error->errorCode);
        }
        try {
            $manager->redeem($this->browser, $callback);
            self::fail('Replay accepted');
        } catch (IdentityException $error) {
            self::assertSame('invalid_login_state', $error->errorCode);
        }
        Event::assertDispatchedTimes(DelegationStateChanged::class, 1);
        Event::assertNotDispatched(DelegationStateChanged::class, fn ($event) => $event->status === 'active');
    }

    public function test_stop_that_cannot_restore_ordinary_authority_notifies_session_end(): void
    {
        Event::fake([LocalSessionEnded::class]);
        $manager = $this->activate();
        $this->browser->setMethod('POST');
        $this->browser->merge(['context_version' => 3]);
        Http::preventStrayRequests();
        Http::fake(fn () => Http::response([], 503));
        $manager->stop($this->browser);
        self::assertNull(IdentitySession::find('ledger-1'));
        Event::assertDispatchedTimes(LocalSessionEnded::class, 1);
    }
}
