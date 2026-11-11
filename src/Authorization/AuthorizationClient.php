<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;

/**
 * Validated receiving-client authorization envelopes.
 *
 * @phpstan-type Selection array{organizationId?: string, roleId?: string}
 * @phpstan-type ContextOption array{selection: Selection, applicationName: string, organizationName: string|null, roleName: string|null}
 * @phpstan-type Contexts array{contract: 'platform-authorization-contexts.v1', issuer: string, subject: string, central_session_id: string, application_id: string, client_id: string, contexts: list<ContextOption>, issued_at: string, expires_at: string}
 * @phpstan-type Snapshot array{contract: 'platform-authorization-snapshot.v1', issuer: string, subject: string, principal_kind: 'user', central_session_id: string, session_status: 'active', security_version: positive-int, application_id: string, identity_status: 'active', application_status: 'active', grant_status: 'active', organization_id: string|null, selected_role_id: string|null, client_id: string, client_policy_version: positive-int|null, role_ids: list<string>, roles: list<string>, permissions: list<string>, authz_version: positive-int, application_policy_version: positive-int, organization_policy_version?: positive-int|null, organization_membership_version?: positive-int|null, issued_at: string, expires_at: string, assurance: array{central_session_id: string, method: 'totp_or_recovery', verified_at: string}|null, delegation: null}
 */
final class AuthorizationClient
{
    public function __construct(private IdentityConfig $config, private IdentityHttp $http) {}

    /** @return Contexts */
    public function contexts(#[\SensitiveParameter] string $token, string $subject, string $sid): array
    {
        $this->requestInput($token, $subject, $sid);
        $data = $this->http->json('/api/authorization/contexts', ['token' => $token]);
        $this->validateContexts($data, $subject, $sid);

        return $data;
    }

    /**
     * @param  array<array-key, mixed>  $selection
     * @return Snapshot
     */
    public function snapshot(#[\SensitiveParameter] string $token, string $subject, string $sid, array $selection = []): array
    {
        $this->requestInput($token, $subject, $sid);
        $this->selection($selection);
        $data = $this->http->json('/api/authorization/snapshot', ['token' => $token, ...$selection]);
        $this->validateSnapshot($data, $subject, $sid, $selection);

        return $data;
    }

    private function requestInput(#[\SensitiveParameter] string $token, string $subject, string $sid): void
    {
        Contract::require($token !== '' && strlen($token) <= 8192 && Contract::identifier($subject) && Contract::identifier($sid));
    }

    /** @phpstan-assert =Selection $selection */
    private function selection(mixed $selection): void
    {
        Contract::require(is_array($selection) && array_diff(array_keys($selection), ['organizationId', 'roleId']) === []);
        foreach ($selection as $identifier) {
            Contract::require(Contract::identifier($identifier));
        }
    }

    /** @param array<array-key, mixed> $data */
    private function bound(array $data, string $contract, string $subject, string $sid): void
    {
        Contract::require(($data['contract'] ?? null) === $contract && ($data['issuer'] ?? null) === $this->config->issuer()
            && ($data['subject'] ?? null) === $subject && ($data['central_session_id'] ?? null) === $sid
            && ($data['application_id'] ?? null) === $this->config->applicationId() && ($data['client_id'] ?? null) === $this->config->clientId()
            && Contract::lifetime($data));
    }

    /**
     * @param  array<array-key, mixed>  $data
     *
     * @phpstan-assert Contexts $data
     */
    private function validateContexts(array $data, string $subject, string $sid): void
    {
        $this->bound($data, 'platform-authorization-contexts.v1', $subject, $sid);
        Contract::require(Contract::keys($data, ['contract', 'issuer', 'subject', 'central_session_id', 'application_id', 'client_id', 'contexts', 'issued_at', 'expires_at']));
        Contract::require(is_array($data['contexts']) && array_is_list($data['contexts']));
        foreach ($data['contexts'] as $context) {
            Contract::require(is_array($context) && Contract::keys($context, ['selection', 'applicationName', 'organizationName', 'roleName']));
            $this->selection($context['selection']);
            Contract::require(is_string($context['applicationName']) && (is_string($context['organizationName']) || $context['organizationName'] === null) && (is_string($context['roleName']) || $context['roleName'] === null));
        }

    }

    /**
     * @param  array<array-key, mixed>  $data
     * @param  Selection  $selection
     *
     * @phpstan-assert Snapshot $data
     */
    private function validateSnapshot(array $data, string $subject, string $sid, array $selection): void
    {
        $this->bound($data, 'platform-authorization-snapshot.v1', $subject, $sid);
        Contract::require(Contract::keys($data, ['contract', 'issuer', 'subject', 'principal_kind', 'central_session_id', 'session_status', 'security_version', 'application_id', 'identity_status', 'application_status', 'grant_status', 'organization_id', 'selected_role_id', 'client_id', 'client_policy_version', 'role_ids', 'roles', 'permissions', 'authz_version', 'application_policy_version', 'issued_at', 'expires_at', 'assurance', 'delegation'], ['organization_policy_version', 'organization_membership_version']));
        Contract::require($data['principal_kind'] === 'user' && $data['session_status'] === 'active' && $data['identity_status'] === 'active' && $data['application_status'] === 'active' && $data['grant_status'] === 'active');
        Contract::require($data['organization_id'] === ($selection['organizationId'] ?? null) && $data['selected_role_id'] === ($selection['roleId'] ?? null));
        foreach (['security_version', 'authz_version', 'application_policy_version'] as $version) {
            Contract::require(Contract::positive($data[$version]));
        }
        foreach (['organization_policy_version', 'organization_membership_version', 'client_policy_version'] as $version) {
            Contract::require(! isset($data[$version]) || Contract::positive($data[$version]));
        }
        Contract::require(Contract::strings($data['role_ids']) && Contract::strings($data['roles']) && Contract::strings($data['permissions'], true));
        Contract::require(isset($selection['roleId']) ? $data['role_ids'] === [$selection['roleId']] && count($data['roles']) === 1 : $data['role_ids'] === [] && $data['roles'] === []);
        Contract::require($data['delegation'] === null);
        if ($data['assurance'] !== null) {
            $assurance = $data['assurance'];
            Contract::require(is_array($assurance) && Contract::keys($assurance, ['central_session_id', 'method', 'verified_at']));
            Contract::require($assurance['central_session_id'] === $sid && $assurance['method'] === 'totp_or_recovery' && Contract::date($assurance['verified_at']) !== null && Contract::date($assurance['verified_at']) <= microtime(true));
        }

    }
}
