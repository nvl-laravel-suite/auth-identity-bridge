<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Services;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Services\ResourceVerifier;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

final class ResourceVerifierTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->configure(['identity.consumers.one.origin' => 'https://identity.test']);
        $this->configure(['identity.consumers.one.application_id' => 'app-1']);
        $this->configure(['identity.consumers.one.resource.client_id' => 'verifier-1']);
        $this->configure(['identity.consumers.one.resource.client_secret' => 'resource-secret']);
        Http::preventStrayRequests();
    }

    #[DataProvider('credentialKinds')]
    public function test_online_verification_uses_exact_plane_and_attenuated_domain_permissions(string $kind, string $path, string $credentialField): void
    {
        Http::fake(['https://identity.test'.$path => Http::response($this->decision($kind))]);
        $principal = $this->app->make(ResourceVerifier::class)->verify($kind, 'synthetic-credential', 'org-1');
        self::assertTrue($principal->hasPermission('documents.read'));
        self::assertFalse($principal->hasPermission('documents.write'));
        self::assertFalse($principal->recentMfa());
        self::assertSame([], $principal->roles());
        Http::assertSent(fn ($request) => $request->url() === 'https://identity.test'.$path
            && $request->hasHeader('Authorization', 'Basic '.base64_encode('verifier-1:resource-secret'))
            && $request[$credentialField] === 'synthetic-credential'
            && $request['audience'] === 'urn:identity-platform:application:app-1');
    }

    public static function credentialKinds(): array
    {
        return [['personal_key', '/api/auth/automation/verify', 'key'], ['machine_key', '/api/service-auth/verify-key', 'key'], ['service_token', '/api/service-auth/verify', 'token']];
    }

    #[DataProvider('invalidDecisions')]
    public function test_decisions_fail_closed_on_wrong_binding_shape_or_lifetime(string $field, mixed $value): void
    {
        $decision = $this->decision('service_token');
        $decision[$field] = $value;
        Http::fake(['*' => Http::response($decision)]);
        $this->expectException(IdentityException::class);
        $this->app->make(ResourceVerifier::class)->verify('service_token', 'synthetic-token', 'org-1');
    }

    public static function invalidDecisions(): array
    {
        return [
            ['issuer', 'https://foreign.test/api/service-auth'], ['application_id', 'foreign-app'],
            ['resource_client_id', 'other-verifier'], ['audience', 'foreign-resource'], ['organization_id', null],
            ['authentication_method', 'machine_api_key'], ['principal_kind', 'user'], ['service_client_id', null],
            ['credential_id', 'different-client'], ['permissions', ['OPENID']], ['permissions', ['openid']], ['service_version', true],
            ['issued_at', '2099-01-01T00:00:00Z'], ['expires_at', '2099-01-01T00:00:00Z'],
            ['expires_at', '1999-01-01T00:00:00Z'], ['assurance', ['method' => 'totp_or_recovery']],
            ['unexpected_authority', true],
        ];
    }

    public function test_personal_key_cannot_be_verified_under_another_resource_client(): void
    {
        $decision = $this->decision('personal_key');
        $decision['client_id'] = 'other-verifier';
        Http::fake(['*' => Http::response($decision)]);
        $this->expectException(IdentityException::class);
        $this->app->make(ResourceVerifier::class)->verify('personal_key', 'synthetic-key', 'org-1');
    }

    public function test_human_native_scopes_never_become_domain_permissions_or_roles(): void
    {
        Http::fake(['https://identity.test/api/auth/oauth2/introspect' => Http::response($this->human())]);
        $principal = $this->app->make(ResourceVerifier::class)->verify('human_token', 'synthetic-token');
        self::assertSame('person-1', $principal->subject());
        self::assertFalse($principal->hasPermission('documents.write'));
        self::assertSame([], $principal->roles());
        self::assertFalse($principal->recentMfa());
        Http::assertSent(fn ($request) => $request->url() === 'https://identity.test/api/auth/oauth2/introspect'
            && $request['token_type_hint'] === 'access_token' && $request['token'] === 'synthetic-token');
    }

    public function test_human_resource_audience_supports_a_full_length_application_identifier(): void
    {
        $applicationId = str_repeat('a', 128);
        $this->configure(['identity.consumers.one.application_id' => $applicationId]);
        $status = $this->human();
        $status['aud'] = 'urn:identity-platform:application:'.$applicationId;
        $status['urn:identity-platform:application'] = $applicationId;
        Http::fake(['*' => Http::response($status)]);
        self::assertSame('person-1', $this->app->make(ResourceVerifier::class)->verify('human_token', 'synthetic-token')->subject());
    }

    #[DataProvider('invalidHumanTokens')]
    public function test_human_token_status_rejects_inactive_or_foreign_native_output(string $field, mixed $value): void
    {
        $status = $this->human();
        $status[$field] = $value;
        Http::fake(['*' => Http::response($status)]);
        $this->expectException(IdentityException::class);
        $this->app->make(ResourceVerifier::class)->verify('human_token', 'synthetic-token');
    }

    public static function invalidHumanTokens(): array
    {
        return [['active', false], ['iss', 'https://foreign.test/api/auth'], ['aud', ['urn:identity-platform:application:app-1', 'foreign']], ['azp', 'foreign'], ['sid', ''], ['exp', 1], ['iat', PHP_INT_MAX], ['urn:identity-platform:application', 'foreign']];
    }

    private function human(): array
    {
        return ['active' => true, 'iss' => 'https://identity.test/api/auth', 'sub' => 'person-1', 'sid' => 'sid-1', 'client_id' => 'web-1', 'azp' => 'web-1', 'aud' => 'urn:identity-platform:application:app-1', 'iat' => time(), 'exp' => time() + 299, 'scope' => 'openid documents.write', 'urn:identity-platform:application' => 'app-1'];
    }

    private function decision(string $kind): array
    {
        $base = ['issuer' => 'https://identity.test/api/service-auth', 'subject' => 'service-1', 'credential_id' => 'worker-1', 'application_id' => 'app-1', 'audience' => 'urn:identity-platform:application:app-1', 'organization_id' => 'org-1', 'permissions' => ['documents.read'], 'credential_version' => 1, 'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59), 'assurance' => null, 'delegation' => null];
        if ($kind === 'personal_key') {
            return array_replace($base, ['contract' => 'platform-credential-decision.v1', 'issuer' => 'https://identity.test/api/auth', 'principal_kind' => 'personal_api_key', 'subject' => 'person-1', 'client_id' => 'verifier-1', 'selected_role_id' => null, 'security_version' => 1]);
        }

        return array_replace($base, ['contract' => 'platform-service-decision.v1', 'principal_kind' => 'service', 'authentication_method' => $kind === 'machine_key' ? 'machine_api_key' : 'oauth_client_credentials', 'service_client_id' => $kind === 'machine_key' ? null : 'worker-1', 'resource_client_id' => 'verifier-1', 'service_version' => 1]);
    }
}
