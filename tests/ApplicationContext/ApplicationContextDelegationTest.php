<?php

namespace IdentityPlatform\Laravel\Tests\ApplicationContext;

use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextManager;
use IdentityPlatform\Laravel\Delegation\IdentityDelegation;
use IdentityPlatform\Laravel\Events\DelegationStateChanged;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Http\Middleware\DelegationBoundary;
use IdentityPlatform\Laravel\Tests\Delegation\HeadlessDelegationTest;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;

/** Reuses the real persisted source/overlay and validated synthetic delegation fixture. */
class ApplicationContextDelegationTest extends HeadlessDelegationTest
{
    public function test_delegation_transition_clears_before_overlay_version_capture_and_never_restores_context(): void
    {
        $this->ledger->update(['application_context' => ['descriptor' => ['kind' => 'workspace', 'resourceId' => 'prior']]]);
        $observed = [];
        Event::listen(DelegationStateChanged::class, function ($event) use (&$observed) {
            $observed[] = [$event->status, $this->ledger->fresh()->context_version, $this->ledger->fresh()->application_context];
            throw new \RuntimeException('Optional listener unavailable');
        });
        $manager = $this->activate();
        self::assertSame([['pending', 3, null], ['active', 3, null]], $observed);
        self::assertSame(3, IdentityDelegation::findOrFail('ledger-1')->context_version);
        $this->browser->setMethod('POST');
        $this->browser->merge(['context_version' => 3]);
        Http::fake(['https://identity.test/api/authorization/snapshot' => Http::response([
            'contract' => 'platform-authorization-snapshot.v1', 'issuer' => 'https://identity.test/api/auth', 'subject' => 'operator-1', 'central_session_id' => 'sid-1', 'application_id' => 'app-1', 'client_id' => 'web-1', 'principal_kind' => 'user', 'session_status' => 'active', 'security_version' => 1, 'identity_status' => 'active', 'application_status' => 'active', 'grant_status' => 'active', 'organization_id' => null, 'selected_role_id' => null, 'client_policy_version' => 1, 'role_ids' => [], 'roles' => [], 'permissions' => ['documents.read'], 'authz_version' => 1, 'application_policy_version' => 1, 'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59), 'assurance' => null, 'delegation' => null,
        ])]);
        $manager->stop($this->browser);
        self::assertSame(4, $this->ledger->fresh()->context_version);
        self::assertNull($this->ledger->fresh()->application_context);
        self::assertSame(['stopped', 4, null], $observed[2]);
    }

    public function test_active_and_expired_overlays_refuse_selection_and_unknown_routes(): void
    {
        $this->activate();
        $this->browser->setMethod('POST');
        $this->browser->headers->set('Origin', 'https://consumer.test');
        $this->browser->session()->regenerateToken();
        $this->browser->merge(['context_version' => 3, 'kind' => 'workspace', 'resourceId' => 'prior', '_token' => $this->browser->session()->token()]);
        foreach ([false, true] as $expired) {
            if ($expired) {
                IdentityDelegation::findOrFail('ledger-1')->update(['expires_at' => now()->subSecond()]);
            }
            self::assertNull(app(ApplicationContextManager::class)->current($this->browser));
            try {
                app(ApplicationContextManager::class)->select($this->browser);
                self::fail();
            } catch (IdentityException $error) {
                self::assertSame('ordinary_action_required', $error->errorCode);
            }
            try {
                app(DelegationBoundary::class)->handle($this->browser, fn () => self::fail('Unknown route admitted'));
                self::fail();
            } catch (IdentityException $error) {
                self::assertSame('delegation_route_forbidden', $error->errorCode);
            }
        }
    }
}
