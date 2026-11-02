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

class DelegationContextTransportTest extends TestCase
{
    private Store $store;

    private int $redeems = 0;

    private int $stops = 0;

    protected function setUp(): void
    {
        parent::setUp();
        $actor = app(UserSynchronizer::class)->sync(['sub' => 'operator-person', 'name' => 'Operator', 'email' => 'operator@example.test']);
        app(SessionRepository::class)->create(['id' => 'transport-ledger', 'user_id' => $actor->id, 'subject' => 'operator-person', 'sid' => 'transport-source',
            'token_vault' => app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:transport-ledger'),
            'selection' => ['selected' => true], 'context_version' => 2, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $this->store = new Store('consumer_session', new ArraySessionHandler(120));
        $this->store->start();
        $this->store->put('identity.session', 'transport-ledger');
        $this->configure(['identity.consumers.one.delegation.operations' => ['documents.read' => ['write' => false, 'resource_type' => 'document']]]);
        Http::preventStrayRequests();
        Http::fake(function (OutboundRequest $request) {
            $path = parse_url($request->url(), PHP_URL_PATH);
            if ($path === '/api/consumer/v1/delegations/start') {
                $input = $request['input'];
                $this->assertSame(3, $input['contextVersion']);

                return Http::response($this->envelope(['handoffId' => 'handoff-transport', 'code' => str_repeat('c', 43), 'state' => $input['state'], 'callbackUrl' => $input['callbackUrl'],
                    'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 60)]));
            }
            if ($path === '/api/consumer/v1/delegations/redeem') {
                $this->redeems++;
                $this->assertSame(3, $request['input']['contextVersion']);

                return Http::response($this->envelope(['handle' => str_repeat('h', 43), 'decision' => $this->decision()]));
            }
            if ($path === '/api/consumer/v1/delegations/stop') {
                $this->stops++;
                $this->assertSame(3, $request['input']['contextVersion']);

                return Http::response($this->envelope(['stopped' => true]));
            }
            if ($path === '/api/authorization/snapshot') {
                return Http::response(['contract' => 'platform-authorization-snapshot.v1', 'issuer' => 'https://identity.test/api/auth', 'subject' => 'operator-person',
                    'central_session_id' => 'transport-source', 'application_id' => 'app-1', 'client_id' => 'web-1', 'principal_kind' => 'user', 'session_status' => 'active',
                    'security_version' => 1, 'identity_status' => 'active', 'application_status' => 'active', 'grant_status' => 'active', 'organization_id' => null,
                    'selected_role_id' => null, 'client_policy_version' => 1, 'role_ids' => [], 'roles' => [], 'permissions' => ['documents.read'], 'authz_version' => 1,
                    'application_policy_version' => 1, 'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59), 'assurance' => null, 'delegation' => null]);
            }

            return Http::response(['error' => ['code' => 'operation_unavailable', 'request_id' => 'transport-fixture']], 503);
        });
    }

    private function envelope(array $data): array
    {
        return ['contract' => 'platform-consumer-result.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1',
            'subject' => 'operator-person', 'centralSessionId' => 'transport-source', 'data' => $data];
    }

    private function decision(): array
    {
        return ['contract' => 'platform-consumer-delegation.v1', 'issuer' => 'https://identity.test/api/auth', 'delegationId' => 'transport-mode',
            'actor' => ['id' => 'operator-person', 'name' => 'Operator', 'email' => 'operator@example.test', 'sourceSessionId' => 'transport-source', 'assurance' => ['centralSessionId' => 'transport-source', 'verifiedAt' => gmdate('Y-m-d\TH:i:s\Z')]],
            'subject' => ['id' => 'target-person', 'name' => 'Target', 'email' => 'target@example.test', 'locale' => 'en', 'classification' => 'person', 'assurance' => null],
            'applicationId' => 'app-1', 'clientId' => 'web-1', 'organizationId' => null, 'roleId' => null, 'actorRoleId' => null, 'contextVersion' => 3,
            'operations' => ['documents.read'], 'permissions' => ['documents.read'], 'versions' => ['authority' => 1], 'reason' => 'Investigate support case', 'ticketReference' => 'CASE-1',
            'startedAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 1), 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 300), 'checkedAt' => gmdate('Y-m-d\TH:i:s\Z'), 'decisionValidUntil' => gmdate('Y-m-d\TH:i:s\Z', time() + 4)];
    }

    private function browser(string $url, string $method, array $input = [], bool $json = false): Request
    {
        $request = $json
            ? Request::create($url, $method, [], [], [], ['CONTENT_TYPE' => 'application/json'], json_encode($input, JSON_THROW_ON_ERROR))
            : Request::create($url, $method, $input);
        $request->setLaravelSession($this->store);
        $this->bindRequest($request);

        return $request;
    }

    private function start(): array
    {
        $request = $this->browser('https://consumer.test/auth/delegation/start', 'POST', ['context_version' => 2]);
        $this->assertInstanceOf(ConsumerClient::class, app(ConsumerClient::class));
        $destination = app(DelegationManager::class)->start($request, ['subjectId' => 'target-person', 'operations' => ['documents.read'], 'reason' => 'Investigate support case',
            'ticketReference' => 'CASE-1', 'expectedPolicyVersion' => 1, 'expectedAuthorityVersion' => 1]);
        parse_str(parse_url($destination, PHP_URL_QUERY), $callback);

        return $callback;
    }

    public function test_get_handoff_callback_redeems_through_real_consumer_client_without_query_context(): void
    {
        $callback = $this->start();
        $request = $this->browser('https://consumer.test/auth/delegation/callback', 'GET', $callback);
        $this->assertFalse($request->query->has('context_version'));
        try {
            app(DelegationManager::class)->redeem($request, $callback);
        } catch (IdentityException $error) {
            $this->fail('Server-owned GET intent context must reach the real consumer client: '.$error->errorCode);
        }
        $this->assertSame(1, $this->redeems);
        $this->assertSame('active', app(OverlayRepository::class)->find('transport-ledger')->status);
        $this->assertFalse($request->query->has('context_version'));
        $this->assertFalse($request->request->has('context_version'));
    }

    public static function stopFormats(): array
    {
        return ['form body' => [false], 'JSON body' => [true]];
    }

    #[DataProvider('stopFormats')]
    public function test_post_stop_uses_new_internal_context_without_mutating_submitted_body(bool $json): void
    {
        $callback = $this->start();
        app(DelegationManager::class)->redeem($this->browser('https://consumer.test/auth/delegation/callback', 'GET', [...$callback, 'context_version' => 3]), $callback);
        $request = $this->browser('https://consumer.test/auth/delegation/stop', 'POST', ['context_version' => 3], $json);
        app(DelegationManager::class)->stop($request);
        $this->assertSame(1, $this->stops);
        $this->assertSame(3, $request->input('context_version'));
        $this->assertSame(4, app(SessionRepository::class)->find('transport-ledger')->context_version);
        $this->assertNull(app(OverlayRepository::class)->find('transport-ledger'));
    }
}
