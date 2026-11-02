<?php

namespace IdentityPlatform\Laravel\Tests\Auth;

use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner;
use IdentityPlatform\Laravel\Delegation\DelegatedActionRunner;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Profiles\LocalProfileRepository;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserProjectionRepository;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\Oidc\ProviderFixture;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Http\Client\Request as OutboundRequest;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\DataProvider;

class TransactionalRefreshTest extends TestCase
{
    private ProviderFixture $provider;

    private Request $browser;

    private string $ledgerId;

    private int $delegationStartedAt;

    private int $refreshCalls = 0;

    private array $refreshTransactions = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->delegationStartedAt = time() - 1;
        $this->configure(['identity.consumers.one.origin' => ProviderFixture::ORIGIN, 'identity.consumers.one.application_id' => 'app-demo', 'identity.consumers.one.browser.client_id' => 'web-demo',
            'identity.consumers.one.delegation.operations' => ['profile.local.update' => ['write' => true, 'resource_type' => 'app_profile']]]);
        $this->provider = new ProviderFixture;
        Http::fake(function (OutboundRequest $request) {
            if ($request->url() === ProviderFixture::ISSUER.'/oauth2/token') {
                parse_str($request->body(), $input);
                if (($input['grant_type'] ?? null) === 'refresh_token') {
                    $this->refreshCalls++;
                    $this->refreshTransactions[] = (new IdentitySession)->getConnection()->transactionLevel() > 0;
                }
            }
            if ($request->url() === ProviderFixture::ORIGIN.'/api/authorization/contexts') {
                return Http::response(['contract' => 'platform-authorization-contexts.v1', 'issuer' => ProviderFixture::ISSUER, 'subject' => 'person-demo', 'central_session_id' => 'central-session-demo',
                    'application_id' => 'app-demo', 'client_id' => 'web-demo', 'contexts' => [['selection' => [], 'applicationName' => 'Synthetic app', 'organizationName' => null, 'roleName' => null]],
                    'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59)]);
            }
            if ($request->url() === ProviderFixture::ORIGIN.'/api/authorization/snapshot') {
                return Http::response(['contract' => 'platform-authorization-snapshot.v1', 'issuer' => ProviderFixture::ISSUER, 'subject' => 'person-demo', 'central_session_id' => 'central-session-demo',
                    'application_id' => 'app-demo', 'client_id' => 'web-demo', 'principal_kind' => 'user', 'session_status' => 'active', 'security_version' => 1, 'identity_status' => 'active',
                    'application_status' => 'active', 'grant_status' => 'active', 'organization_id' => null, 'selected_role_id' => null, 'client_policy_version' => 1, 'role_ids' => [], 'roles' => [],
                    'permissions' => ['profile.local.update'], 'authz_version' => 1, 'application_policy_version' => 1,
                    'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59), 'assurance' => null, 'delegation' => null]);
            }
            if ($request->url() === ProviderFixture::ORIGIN.'/api/consumer/v1/delegations/check') {
                return Http::response($this->envelope($this->decision()));
            }
            if ($request->url() === ProviderFixture::ORIGIN.'/api/consumer/v1/delegations/authorize-operation') {
                $input = $request['input'];

                return Http::response($this->envelope(['receiptId' => 'transactional-receipt', 'delegationId' => 'transactional-mode', 'contextVersion' => 2,
                    'operation' => 'profile.local.update', 'organizationId' => null, 'resourceType' => 'app_profile', 'resourceId' => $input['resourceId'], 'commandDigest' => $input['commandDigest'],
                    'idempotencyKey' => $input['idempotencyKey'], 'admittedAt' => gmdate('Y-m-d\TH:i:s\Z'), 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 4),
                    'reportingCapability' => str_repeat('r', 43), 'reportingExpiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 600), 'decision' => $this->decision()]));
            }

            return null;
        });
        $this->provider->fake();
        $this->browser = Request::create('https://consumer.test/account/profile', 'POST');
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        $this->browser->setLaravelSession($store);
        $this->bindRequest($this->browser);
        $manager = app(SessionManager::class);
        parse_str(parse_url($manager->start($this->browser), PHP_URL_QUERY), $intent);
        $this->provider->claims['nonce'] = $intent['nonce'];
        $manager->complete($this->browser, ['state' => $intent['state'], 'code' => 'synthetic-code']);
        $this->ledgerId = $this->browser->session()->get('identity.session');
        $manager->select($this->browser, [], 1);
        $this->browser->request->set('context_version', 2);
        Queue::fake();
    }

    private function envelope(array $data): array
    {
        return ['contract' => 'platform-consumer-result.v1', 'issuer' => ProviderFixture::ISSUER, 'applicationId' => 'app-demo', 'clientId' => 'web-demo',
            'subject' => 'person-demo', 'centralSessionId' => 'central-session-demo', 'data' => $data];
    }

    private function decision(): array
    {
        return ['contract' => 'platform-consumer-delegation.v1', 'issuer' => ProviderFixture::ISSUER, 'delegationId' => 'transactional-mode',
            'actor' => ['id' => 'person-demo', 'name' => 'Operator', 'email' => 'person@example.test', 'sourceSessionId' => 'central-session-demo', 'assurance' => ['centralSessionId' => 'central-session-demo', 'verifiedAt' => gmdate('Y-m-d\TH:i:s\Z')]],
            'subject' => ['id' => 'target-person', 'name' => 'Target', 'email' => 'target@example.test', 'locale' => 'en', 'classification' => 'person', 'assurance' => null],
            'applicationId' => 'app-demo', 'clientId' => 'web-demo', 'organizationId' => null, 'roleId' => null, 'actorRoleId' => null, 'contextVersion' => 2,
            'operations' => ['profile.local.update'], 'permissions' => ['profile.local.update'], 'versions' => ['authority' => 1], 'reason' => 'Investigate support case', 'ticketReference' => 'CASE-1',
            'startedAt' => gmdate('Y-m-d\TH:i:s\Z', $this->delegationStartedAt), 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', $this->delegationStartedAt + 301),
            'checkedAt' => gmdate('Y-m-d\TH:i:s\Z'), 'decisionValidUntil' => gmdate('Y-m-d\TH:i:s\Z', time() + 4)];
    }

    private function enterSyntheticRefreshWindow(): void
    {
        $row = app(SessionRepository::class)->find($this->ledgerId);
        $vault = app(IdentityVault::class);
        $tokens = $vault->open($row->token_vault, 'session:'.$row->id);
        $tokens['expires_at'] = now()->timestamp + 10;
        $row->update(['token_vault' => $vault->seal($tokens, 'session:'.$row->id)]);
    }

    public static function actionModes(): array
    {
        return ['ordinary owner' => [false], 'delegated owner' => [true]];
    }

    #[DataProvider('actionModes')]
    public function test_owner_path_never_rotates_refresh_inside_resource_transaction_and_next_request_can_refresh(bool $delegated): void
    {
        $rows = app(SessionRepository::class);
        $original = $rows->find($this->ledgerId);
        $owner = app(UserProjectionRepository::class)->find($original->user_id);
        if ($delegated) {
            $owner = app(UserSynchronizer::class)->sync(['sub' => 'target-person', 'name' => 'Target', 'email' => 'target@example.test']);
            $decision = $this->decision();
            app(OverlayRepository::class)->save($this->ledgerId, ['source_sid' => 'central-session-demo', 'status' => 'active', 'browser_binding' => str_repeat('b', 43), 'context_version' => 2,
                'handle_vault' => app(IdentityVault::class)->seal(['handle' => str_repeat('h', 43)], 'delegation:'.$this->ledgerId), 'decision' => $decision, 'expires_at' => $decision['expiresAt']]);
        }
        $profiles = app(LocalProfileRepository::class);
        $profile = $profiles->read($owner);
        $lock = function () use ($profiles, $owner) {
            $locked = $profiles->lock($owner);
            $this->enterSyntheticRefreshWindow();

            return $locked;
        };
        $mutate = function () use ($profiles, $owner): array {
            $changed = $profiles->update($owner, 1, ['display_name' => 'Must roll back']);
            app(IdentityAccess::class)->assertOwner($owner);

            return ['version' => $changed->version];
        };
        $code = null;
        $status = null;
        try {
            if ($delegated) {
                app(DelegatedActionRunner::class)->run($this->browser, 'profile.local.update', 'app_profile', $profile->id, ['display_name' => 'Must roll back'], str_repeat('i', 43), $lock, $mutate);
            } else {
                app(OrdinaryActionRunner::class)->run($this->browser, $lock, $mutate);
            }
        } catch (IdentityException $error) {
            $code = $error->errorCode;
            $status = $error->status;
        }
        $this->assertNull($profile->refresh()->display_name);
        $this->assertSame(1, $profile->version);
        $rolledBack = $rows->find($this->ledgerId);
        $this->assertTrue(hash_equals($original->token_vault, $rolledBack->token_vault), 'Original synthetic vault must survive local rollback');
        $this->assertSame(1, $rolledBack->token_generation);
        $this->assertSame(['code' => 'refresh_required', 'status' => 409, 'remote_refreshes' => 0, 'refresh_transactions' => []],
            ['code' => $code, 'status' => $status, 'remote_refreshes' => $this->refreshCalls, 'refresh_transactions' => $this->refreshTransactions]);

        $this->enterSyntheticRefreshWindow();
        $manager = app(SessionManager::class);
        $successor = $manager->current($this->browser);
        $this->assertNotNull($successor);
        $this->assertSame(2, $successor->token_generation);
        $this->assertSame(1, $this->refreshCalls);
        $this->assertSame([false], $this->refreshTransactions);
        $tokens = app(IdentityVault::class)->open($successor->token_vault, 'session:'.$successor->id);
        $this->assertTrue(hash_equals('synthetic-successor-refresh-token', $tokens['refresh_token']), 'Rotated synthetic successor must be persisted outside the transaction');
        $this->assertSame('central-session-demo', $tokens['sid']);
        $this->assertSame($original->started_at->toIso8601String(), $successor->started_at->toIso8601String());
        $this->assertSame($original->expires_at->toIso8601String(), $successor->expires_at->toIso8601String());
        $manager->current($this->browser);
        $this->assertSame(1, $this->refreshCalls);
    }
}
