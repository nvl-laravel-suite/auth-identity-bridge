<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Services;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Authorization\Principal;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;

/**
 * @internal Inbound credential verification is owned by the configured API middleware.
 *
 * @phpstan-import-type Decision from Principal
 */
final class ResourceVerifier
{
    public function __construct(private IdentityConfig $config, private IdentityHttp $http) {}

    public function verify(string $kind, #[\SensitiveParameter] string $credential, ?string $organizationId = null): Principal
    {
        Contract::require($credential !== '' && strlen($credential) <= 60000, 'credential_inactive');
        Contract::require($organizationId === null || Contract::identifier($organizationId), 'credential_inactive');
        if ($kind === 'human_token') {
            return $this->human($credential);
        }
        [$path, $field] = match ($kind) {
            'personal_key' => ['/api/auth/automation/verify', 'key'],
            'machine_key' => ['/api/service-auth/verify-key', 'key'],
            'service_token' => ['/api/service-auth/verify', 'token'],
            default => throw new IdentityException('credential_kind_invalid', 400),
        };
        $data = $this->http->json($path, [$field => $credential, 'audience' => $this->audience()], 'resource');
        $this->validateDecision($data, $kind, $organizationId);

        return new Principal($data);
    }

    /**
     * @param  array<array-key, mixed>  $data
     *
     * @phpstan-assert Decision $data
     */
    private function validateDecision(array $data, string $kind, ?string $organizationId): void
    {
        $personal = $kind === 'personal_key';
        $required = ['contract', 'issuer', 'principal_kind', 'subject', 'credential_id', 'application_id', 'audience', 'organization_id', 'permissions', 'credential_version', 'issued_at', 'expires_at', 'assurance', 'delegation'];
        $required = [...$required, ...($personal ? ['client_id', 'selected_role_id', 'security_version'] : ['authentication_method', 'service_client_id', 'resource_client_id', 'service_version'])];
        Contract::require(Contract::keys($data, $required), 'invalid_credential_decision');
        Contract::require($data['contract'] === ($personal ? 'platform-credential-decision.v1' : 'platform-service-decision.v1')
            && $data['issuer'] === ($personal ? $this->config->issuer() : $this->config->serviceIssuer())
            && $data['principal_kind'] === ($personal ? 'personal_api_key' : 'service')
            && $data['application_id'] === $this->config->applicationId() && $data['audience'] === $this->audience()
            && $data[$personal ? 'client_id' : 'resource_client_id'] === $this->config->credentials('resource')['id']
            && $data['organization_id'] === $organizationId && Contract::lifetime($data, 60, 5), 'invalid_credential_decision');
        Contract::require(Contract::identifier($data['subject']) && Contract::identifier($data['credential_id'])
            && Contract::positive($data['credential_version']) && Contract::strings($data['permissions'], true)
            && $data['assurance'] === null && $data['delegation'] === null, 'invalid_credential_decision');
        if ($personal) {
            Contract::require(Contract::positive($data['security_version']) && Contract::nullableIdentifier($data['selected_role_id']), 'invalid_credential_decision');
        } else {
            $machine = $kind === 'machine_key';
            Contract::require(Contract::positive($data['service_version']) && $data['authentication_method'] === ($machine ? 'machine_api_key' : 'oauth_client_credentials')
                && ($machine ? $data['service_client_id'] === null : Contract::identifier($data['service_client_id']) && $data['service_client_id'] === $data['credential_id']), 'invalid_credential_decision');
            Contract::require(count($data['permissions']) <= 250 && array_intersect($data['permissions'], ['openid', 'profile', 'email', 'offline_access']) === [], 'invalid_credential_decision');
        }
    }

    private function human(#[\SensitiveParameter] string $token): Principal
    {
        Contract::require(strlen($token) <= 8192, 'token_inactive');
        $started = microtime(true);
        try {
            $info = $this->http->form('/api/auth/oauth2/introspect', ['token' => $token, 'token_type_hint' => 'access_token'], 'resource');
        } catch (IdentityException $error) {
            if (in_array($error->status, [401, 403], true)) {
                throw new IdentityException('resource_authentication_failed', 503);
            }
            throw $error;
        }
        $active = $info['active'] ?? null;
        if ($active === false) {
            throw new IdentityException('token_inactive', 401);
        }
        Contract::require($active === true && Contract::identifier($info['sub'] ?? null) && Contract::identifier($info['sid'] ?? null)
            && Contract::identifier($info['client_id'] ?? null) && ($info['azp'] ?? null) === $info['client_id']
            && is_string($info['scope'] ?? null) && is_int($info['iat'] ?? null) && is_int($info['exp'] ?? null), 'invalid_response', 502);
        $audiences = is_string($info['aud'] ?? null) ? [$info['aud']] : ($info['aud'] ?? null);
        Contract::require(is_array($audiences) && array_is_list($audiences) && $audiences !== [], 'invalid_response', 502);
        foreach ($audiences as $audience) {
            Contract::require(is_string($audience) && $audience !== '', 'invalid_response', 502);
        }
        $resources = array_values(array_filter($audiences, fn ($audience) => $audience !== $this->config->issuer().'/oauth2/userinfo'));
        $now = microtime(true);
        Contract::require(($info['iss'] ?? null) === $this->config->issuer() && ($info['urn:identity-platform:application'] ?? null) === $this->config->applicationId()
            && $resources === [$this->audience()] && $info['exp'] > $now && $info['iat'] <= $now + 5
            && $info['exp'] > $info['iat'] && $info['exp'] - $info['iat'] <= 300, 'token_inactive');
        Contract::require($now < $started + 5, 'human_oauth_unavailable', 503);
        $scopes = array_values(array_unique(array_filter(explode(' ', $info['scope']), fn ($scope) => $scope !== '')));
        Contract::require(count($scopes) <= 100 && Contract::strings($scopes), 'invalid_response', 502);

        return new Principal([
            'contract' => 'platform-human-oauth-token.v1', 'principal_kind' => 'user', 'authentication_method' => 'oauth_access_token',
            'issuer' => $this->config->issuer(), 'subject' => $info['sub'], 'central_session_id' => $info['sid'],
            'application_id' => $this->config->applicationId(), 'issuing_client_id' => $info['client_id'], 'audience' => $this->audience(),
            'scopes' => $scopes, 'checked_at' => $this->iso($started), 'expires_at' => $this->iso(min($started + 5, $info['exp'])), 'token_expires_at' => $this->iso($info['exp']),
        ]);
    }

    private function audience(): string
    {
        return 'urn:identity-platform:application:'.$this->config->applicationId();
    }

    private function iso(float $timestamp): string
    {
        return gmdate('Y-m-d\TH:i:s', (int) $timestamp).sprintf('.%06dZ', (int) (($timestamp - floor($timestamp)) * 1000000));
    }
}
