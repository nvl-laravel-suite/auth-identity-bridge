<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Authorization;

use IdentityPlatform\Laravel\Authorization\AuthorizationClient;
use IdentityPlatform\Laravel\Authorization\Principal;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

final class AuthorizationClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->configure(['identity.consumers.one.origin' => 'https://identity.test']);
        $this->configure(['identity.consumers.one.application_id' => 'app-1']);
        $this->configure(['identity.consumers.one.browser.client_id' => 'web-1']);
        $this->configure(['identity.consumers.one.browser.client_secret' => 'secret']);
        Http::preventStrayRequests();
    }

    public function test_snapshot_binds_identity_client_selection_and_permissions(): void
    {
        Http::fake(['https://identity.test/api/authorization/snapshot' => Http::response($this->snapshot())]);
        $result = $this->app->make(AuthorizationClient::class)->snapshot('synthetic-token', 'person-1', 'sid-1', ['organizationId' => 'org-1', 'roleId' => 'role-1']);
        $principal = new Principal($result);
        self::assertTrue($principal->hasPermission('documents.read'));
        self::assertFalse($principal->hasPermission('documents.write'));
        self::assertTrue($principal->hasRole('reader'));
        self::assertSame('org-1', $principal->organizationId());
        self::assertTrue($principal->recentMfa());
        Http::assertSent(fn ($request) => $request->url() === 'https://identity.test/api/authorization/snapshot'
            && $request->hasHeader('Authorization', 'Basic '.base64_encode('web-1:secret'))
            && $request['token'] === 'synthetic-token' && $request['organizationId'] === 'org-1' && $request['roleId'] === 'role-1');
    }

    #[DataProvider('invalidSnapshots')]
    public function test_snapshot_refuses_cross_binding_malformed_or_stale_authority(string $field, mixed $value): void
    {
        $snapshot = $this->snapshot();
        $snapshot[$field] = $value;
        Http::fake(['*' => Http::response($snapshot)]);
        $this->expectException(IdentityException::class);
        $this->app->make(AuthorizationClient::class)->snapshot('synthetic-token', 'person-1', 'sid-1', ['organizationId' => 'org-1', 'roleId' => 'role-1']);
    }

    public static function invalidSnapshots(): array
    {
        return [
            ['contract', 'different.v1'], ['issuer', 'https://foreign.test/api/auth'],
            ['subject', 'another-person'], ['central_session_id', 'another-session'],
            ['application_id', 'foreign-app'], ['client_id', 'foreign-client'],
            ['organization_id', null], ['selected_role_id', 'other-role'],
            ['role_ids', ['role-1', 'other-role']], ['permissions', 'documents.read'],
            ['security_version', 0], ['principal_kind', 'service'],
            ['session_status', 'revoked'], ['expires_at', '1999-01-01T00:00:00Z'],
            ['issued_at', '2099-01-01T00:00:00Z'], ['expires_at', '2099-01-01T00:00:00Z'],
            ['assurance', ['central_session_id' => 'other-session', 'method' => 'totp_or_recovery', 'verified_at' => '2026-01-01T00:00:00Z']],
            ['delegation', ['permissions' => ['documents.write']]],
        ];
    }

    public function test_contexts_are_validated_discovery_choices_without_granting_permissions(): void
    {
        $contexts = [
            'contract' => 'platform-authorization-contexts.v1', 'issuer' => 'https://identity.test/api/auth',
            'subject' => 'person-1', 'central_session_id' => 'sid-1', 'application_id' => 'app-1', 'client_id' => 'web-1',
            'contexts' => [['selection' => ['organizationId' => 'org-1', 'roleId' => 'role-1'], 'applicationName' => 'App', 'organizationName' => 'Organization', 'roleName' => 'Reader']],
            'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59),
        ];
        $invalid = $contexts;
        $invalid['contexts'][0]['selection']['organizationId'] = ['forged'];
        Http::fakeSequence()->push($contexts)->push($invalid);
        self::assertCount(1, $this->app->make(AuthorizationClient::class)->contexts('synthetic-token', 'person-1', 'sid-1')['contexts']);
        $this->expectException(IdentityException::class);
        $this->app->make(AuthorizationClient::class)->contexts('synthetic-token', 'person-1', 'sid-1');
    }

    public function test_unselected_role_snapshot_and_old_mfa_cannot_gain_a_selected_role_or_recent_assurance(): void
    {
        $snapshot = $this->snapshot();
        $snapshot['organization_id'] = null;
        $snapshot['selected_role_id'] = null;
        $snapshot['role_ids'] = [];
        $snapshot['roles'] = [];
        $snapshot['assurance']['verified_at'] = gmdate('Y-m-d\TH:i:s\Z', time() - 301);
        Http::fake(['*' => Http::response($snapshot)]);
        $principal = new Principal($this->app->make(AuthorizationClient::class)->snapshot('synthetic-token', 'person-1', 'sid-1'));
        self::assertFalse($principal->recentMfa());
        self::assertFalse($principal->hasRole('reader'));
    }

    private function snapshot(): array
    {
        return [
            'contract' => 'platform-authorization-snapshot.v1', 'issuer' => 'https://identity.test/api/auth', 'subject' => 'person-1',
            'principal_kind' => 'user', 'central_session_id' => 'sid-1', 'session_status' => 'active', 'security_version' => 1,
            'application_id' => 'app-1', 'identity_status' => 'active', 'application_status' => 'active', 'grant_status' => 'active',
            'organization_id' => 'org-1', 'selected_role_id' => 'role-1', 'client_id' => 'web-1', 'client_policy_version' => 1,
            'role_ids' => ['role-1'], 'roles' => ['reader'], 'permissions' => ['documents.read'], 'authz_version' => 1,
            'application_policy_version' => 1, 'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59),
            'assurance' => ['central_session_id' => 'sid-1', 'method' => 'totp_or_recovery', 'verified_at' => gmdate('Y-m-d\TH:i:s\Z')], 'delegation' => null,
        ];
    }
}
