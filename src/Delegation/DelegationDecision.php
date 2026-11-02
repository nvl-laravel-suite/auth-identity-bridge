<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Authorization\Principal;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;

/**
 * Provider decision validated against the exact local source and delegation overlay.
 *
 * @phpstan-type DecisionData array{contract: 'platform-consumer-delegation.v1', issuer: string, delegationId: non-empty-string, actor: array{id: string, name: string, email: string, sourceSessionId: string, assurance: array{centralSessionId: string, verifiedAt: string}}, subject: array{id: non-empty-string, name: string, email: string, locale: 'en'|'bg', classification: 'person', assurance: null}, applicationId: string, clientId: string, organizationId: string|null, roleId: mixed, actorRoleId: mixed, contextVersion: int, operations: non-empty-list<non-empty-string>, permissions: list<non-empty-string>, versions: array<array-key, mixed>, reason: string, ticketReference: string, startedAt: string, expiresAt: string, checkedAt: string, decisionValidUntil: string}
 */
final readonly class DelegationDecision
{
    /** @param DecisionData $data */
    private function __construct(public array $data) {}

    /** @param array<array-key, mixed> $data */
    public static function validate(array $data, IdentitySession $session, IdentityDelegation $overlay, IdentityConfig $config): self
    {
        Contract::require(Contract::keys($data, ['contract', 'issuer', 'delegationId', 'actor', 'subject', 'applicationId', 'clientId', 'organizationId', 'roleId', 'actorRoleId', 'contextVersion', 'operations', 'permissions', 'versions', 'reason', 'ticketReference', 'startedAt', 'expiresAt', 'checkedAt', 'decisionValidUntil']), 'invalid_delegation_response', 502);
        Contract::require($data['contract'] === 'platform-consumer-delegation.v1' && $data['issuer'] === $config->issuer()
            && $data['applicationId'] === $config->applicationId() && $data['clientId'] === $config->clientId()
            && Contract::identifier($data['delegationId']) && $data['contextVersion'] === $session->context_version
            && $data['contextVersion'] === $overlay->context_version && $overlay->source_sid === $session->sid, 'invalid_delegation_response', 502);
        $actor = $data['actor'];
        $subject = $data['subject'];
        Contract::require(is_array($actor) && Contract::keys($actor, ['id', 'name', 'email', 'sourceSessionId', 'assurance'])
            && $actor['id'] === $session->subject && $actor['sourceSessionId'] === $session->sid
            && is_string($actor['name']) && is_string($actor['email']) && is_array($actor['assurance'])
            && Contract::keys($actor['assurance'], ['centralSessionId', 'verifiedAt'])
            && $actor['assurance']['centralSessionId'] === $session->sid && is_string($actor['assurance']['verifiedAt']) && Contract::date($actor['assurance']['verifiedAt']) !== null, 'invalid_delegation_response', 502);
        Contract::require(is_array($subject) && Contract::keys($subject, ['id', 'name', 'email', 'locale', 'classification', 'assurance'])
            && Contract::identifier($subject['id']) && $subject['id'] !== $actor['id'] && is_string($subject['name']) && is_string($subject['email'])
            && in_array($subject['locale'], ['en', 'bg'], true) && $subject['classification'] === 'person' && $subject['assurance'] === null, 'invalid_delegation_response', 502);
        $expected = $overlay->decision;
        Contract::require(is_array($expected) && $subject['id'] === $expected['subject']['id']
            && $data['organizationId'] === ($expected['organizationId'] ?? null) && $data['roleId'] === ($expected['roleId'] ?? null)
            && $data['actorRoleId'] === ($session->selection['roleId'] ?? null)
            && Contract::strings($data['operations'], true) && $data['operations'] !== [] && Contract::strings($data['permissions'], true)
            && array_diff($data['operations'], $expected['operations']) === [] && is_array($data['versions'])
            && is_string($data['reason']) && is_string($data['ticketReference']), 'invalid_delegation_response', 502);
        if (isset($expected['delegationId'])) {
            Contract::require($data['delegationId'] === $expected['delegationId'] && $data['versions'] === $expected['versions']
                && $data['startedAt'] === $expected['startedAt'] && $data['expiresAt'] === $expected['expiresAt']
                && $data['permissions'] === $expected['permissions'], 'invalid_delegation_response', 502);
        }
        Contract::require(is_string($data['startedAt']) && is_string($data['expiresAt']) && is_string($data['checkedAt']) && is_string($data['decisionValidUntil']), 'invalid_delegation_response', 502);
        $start = Contract::date($data['startedAt']);
        $end = Contract::date($data['expiresAt']);
        $checked = Contract::date($data['checkedAt']);
        $valid = Contract::date($data['decisionValidUntil']);
        $now = microtime(true);
        Contract::require($start !== null && $end !== null && $checked !== null && $valid !== null
            && $start <= $checked && $checked <= $now + 0.1 && $now - $checked <= 5
            && $end > $now && $end - $start <= 900 && $valid > $now && $valid <= $end && $valid - $checked <= 5, 'invalid_delegation_response', 502);

        return new self(['actor' => ['id' => $actor['id'], 'name' => $actor['name'], 'email' => $actor['email'], 'sourceSessionId' => $actor['sourceSessionId'], 'assurance' => ['centralSessionId' => $actor['assurance']['centralSessionId'], 'verifiedAt' => $actor['assurance']['verifiedAt']]], 'subject' => ['id' => $subject['id'], 'name' => $subject['name'], 'email' => $subject['email'], 'locale' => $subject['locale'], 'classification' => $subject['classification'], 'assurance' => $subject['assurance']], 'contract' => $data['contract'], 'issuer' => $data['issuer'], 'delegationId' => $data['delegationId'], 'applicationId' => $data['applicationId'], 'clientId' => $data['clientId'], 'organizationId' => $data['organizationId'], 'roleId' => $data['roleId'], 'actorRoleId' => $data['actorRoleId'], 'contextVersion' => $data['contextVersion'], 'operations' => $data['operations'], 'permissions' => $data['permissions'], 'versions' => $data['versions'], 'reason' => $data['reason'], 'ticketReference' => $data['ticketReference'], 'startedAt' => $data['startedAt'], 'expiresAt' => $data['expiresAt'], 'checkedAt' => $data['checkedAt'], 'decisionValidUntil' => $data['decisionValidUntil']]);
    }

    public function principal(): Principal
    {
        return new Principal(['contract' => $this->data['contract'], 'issuer' => $this->data['issuer'], 'subject' => $this->data['subject']['id'], 'principal_kind' => 'user',
            'permissions' => $this->data['permissions'], 'roles' => [], 'organization_id' => $this->data['organizationId'],
            'assurance' => null, 'central_session_id' => null, 'expires_at' => $this->data['decisionValidUntil'], 'delegation' => $this->data]);
    }
}
