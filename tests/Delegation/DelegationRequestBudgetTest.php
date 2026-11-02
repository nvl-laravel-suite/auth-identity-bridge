<?php

namespace IdentityPlatform\Laravel\Tests\Delegation;

use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Delegation\DelegationManager;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Http\Client\Request as OutboundRequest;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

class DelegationRequestBudgetTest extends TestCase
{
    private Request $browser;

    private array $decision;

    private int $checks = 0;

    private int $admissions = 0;

    private bool $refuseAdmission = false;

    private bool $shortDecision = false;

    protected function setUp(): void
    {
        parent::setUp();
        $actor = app(UserSynchronizer::class)->sync(['sub' => 'operator-person', 'name' => 'Operator', 'email' => 'operator@example.test']);
        app(SessionRepository::class)->create(['id' => 'budget-ledger', 'user_id' => $actor->id, 'subject' => 'operator-person', 'sid' => 'budget-source',
            'token_vault' => app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:budget-ledger'),
            'selection' => ['selected' => true], 'context_version' => 3, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $this->decision = ['contract' => 'platform-consumer-delegation.v1', 'issuer' => 'https://identity.test/api/auth', 'delegationId' => 'budget-mode',
            'actor' => ['id' => 'operator-person', 'name' => 'Operator', 'email' => 'operator@example.test', 'sourceSessionId' => 'budget-source', 'assurance' => ['centralSessionId' => 'budget-source', 'verifiedAt' => gmdate('Y-m-d\TH:i:s\Z')]],
            'subject' => ['id' => 'target-person', 'name' => 'Target', 'email' => 'target@example.test', 'locale' => 'en', 'classification' => 'person', 'assurance' => null],
            'applicationId' => 'app-1', 'clientId' => 'web-1', 'organizationId' => null, 'roleId' => null, 'actorRoleId' => null, 'contextVersion' => 3,
            'operations' => ['documents.read', 'documents.update'], 'permissions' => ['documents.read', 'documents.update'], 'versions' => ['authority' => 1], 'reason' => 'Investigate support case', 'ticketReference' => 'CASE-1',
            'startedAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 1), 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 300), 'checkedAt' => gmdate('Y-m-d\TH:i:s\Z'), 'decisionValidUntil' => gmdate('Y-m-d\TH:i:s\Z', time() + 4)];
        app(OverlayRepository::class)->save('budget-ledger', ['source_sid' => 'budget-source', 'status' => 'active', 'browser_binding' => str_repeat('b', 43), 'context_version' => 3,
            'handle_vault' => app(IdentityVault::class)->seal(['handle' => str_repeat('h', 43)], 'delegation:budget-ledger'), 'decision' => $this->decision, 'expires_at' => $this->decision['expiresAt']]);
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        $store->put('identity.session', 'budget-ledger');
        $this->browser = Request::create('https://consumer.test/documents/1', 'POST', ['context_version' => 3]);
        $this->browser->setLaravelSession($store);
        $this->configure(['identity.consumers.one.delegation.operations' => ['documents.read' => ['write' => false, 'resource_type' => 'document'], 'documents.update' => ['write' => true, 'resource_type' => 'document']]]);
        Http::preventStrayRequests();
        Http::fake(function (OutboundRequest $request) {
            $path = parse_url($request->url(), PHP_URL_PATH);
            if ($path === '/api/consumer/v1/delegations/check') {
                $this->checks++;

                return Http::response($this->envelope([...$this->decision, 'checkedAt' => gmdate('Y-m-d\TH:i:s\Z'), 'decisionValidUntil' => gmdate('Y-m-d\TH:i:s\Z', time() + ($this->shortDecision ? 1 : 4))]));
            }
            if ($path === '/api/consumer/v1/delegations/authorize-operation') {
                $this->admissions++;

                return $this->refuseAdmission ? Http::response(['error' => ['code' => 'delegation_authority_required']], 403) : Http::response($this->envelope(['admitted' => true]));
            }

            return Http::response(['error' => ['code' => 'operation_unavailable']], 503);
        });
    }

    private function envelope(array $data): array
    {
        return ['contract' => 'platform-consumer-result.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1',
            'subject' => 'operator-person', 'centralSessionId' => 'budget-source', 'data' => $data];
    }

    public function test_same_request_operation_reuses_one_validated_check_across_manager_instances(): void
    {
        $first = app(DelegationManager::class)->check($this->browser, 'documents.update');
        $second = app(DelegationManager::class)->check($this->browser, 'documents.update');
        $this->assertSame('target-person', $second->principal()->subject());
        $this->assertSame(1, $this->checks);
        $this->assertSame($first->data, $second->data);
    }

    public function test_another_operation_and_a_cloned_request_each_obtain_fresh_checks(): void
    {
        $manager = app(DelegationManager::class);
        $manager->check($this->browser, 'documents.read');
        $manager->check($this->browser, 'documents.update');
        $manager->check(clone $this->browser, 'documents.update');
        $this->assertSame(3, $this->checks);
    }

    public static function changedBindings(): array
    {
        return ['token generation' => ['token'], 'selected role' => ['selection'], 'actor' => ['subject'], 'source session' => ['source'], 'context' => ['context'],
            'overlay handle' => ['handle'], 'overlay decision' => ['decision'], 'overlay browser binding' => ['browser'], 'stopped overlay' => ['stopped'], 'configured binding' => ['configuration']];
    }

    #[DataProvider('changedBindings')]
    public function test_changed_binding_never_reuses_a_previous_check(string $change): void
    {
        $manager = app(DelegationManager::class);
        $manager->check($this->browser, 'documents.update');
        $rows = app(SessionRepository::class);
        $overlay = app(OverlayRepository::class)->find('budget-ledger');
        match ($change) {
            'token' => $rows->find('budget-ledger')->update(['token_generation' => 2]),
            'selection' => $rows->find('budget-ledger')->update(['selection' => ['selected' => true, 'roleId' => 'other-role']]),
            'subject' => $rows->find('budget-ledger')->update(['subject' => 'other-operator']),
            'source' => $rows->find('budget-ledger')->update(['sid' => 'other-source']),
            'context' => $rows->find('budget-ledger')->update(['context_version' => 4]),
            'handle' => $overlay->update(['handle_vault' => app(IdentityVault::class)->seal(['handle' => str_repeat('n', 43)], 'delegation:budget-ledger')]),
            'decision' => $overlay->update(['decision' => [...$overlay->decision, 'permissions' => ['documents.read']]]),
            'browser' => $overlay->update(['browser_binding' => str_repeat('n', 43)]),
            'stopped' => app(OverlayRepository::class)->stop('budget-ledger'),
            'configuration' => $this->configure(['identity.consumers.one.application_id' => 'other-app']),
        };
        if ($change === 'configuration') {
            $manager = app(DelegationManager::class);
        }
        try {
            $manager->check($this->browser, 'documents.update');
            $this->assertSame(2, $this->checks, 'A changed binding reused its previous proof');
        } catch (IdentityException $error) {
            $this->assertContains($error->errorCode, ['context_changed', 'invalid_consumer_response', 'invalid_delegation_response', 'delegation_unavailable', 'sign_in_required']);
        }
    }

    public function test_expired_request_decision_is_refetched(): void
    {
        $this->shortDecision = true;
        $manager = app(DelegationManager::class);
        $manager->check($this->browser, 'documents.update');
        usleep(1100000);
        $this->shortDecision = false;
        $this->assertSame('target-person', $manager->check($this->browser, 'documents.update')->principal()->subject());
        $this->assertSame(2, $this->checks);
    }

    public static function admissionOutcomes(): array
    {
        return ['accepted' => [false], 'refused' => [true]];
    }

    #[DataProvider('admissionOutcomes')]
    public function test_admission_attempt_invalidates_the_request_check_even_when_refused(bool $refused): void
    {
        $manager = app(DelegationManager::class);
        $manager->check($this->browser, 'documents.update');
        $this->refuseAdmission = $refused;
        try {
            app(ConsumerClient::class)->call($this->browser, 'delegation.admit', ['operation' => 'documents.update']);
            $this->assertFalse($refused);
        } catch (IdentityException $error) {
            $this->assertTrue($refused);
            $this->assertSame('delegation_authority_required', $error->errorCode);
        }
        $manager->check($this->browser, 'documents.update');
        $this->assertSame(1, $this->admissions);
        $this->assertSame(2, $this->checks);
    }
}
