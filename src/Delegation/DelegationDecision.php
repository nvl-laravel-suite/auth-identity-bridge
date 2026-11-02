<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Authorization\Principal;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;

final readonly class DelegationDecision
{
    private function __construct(public array $data) {}

    public static function validate(array $data, IdentitySession $session, IdentityDelegation $overlay, IdentityConfig $config): self
    {
        $require = static fn (bool $valid) => Contract::require($valid, 'invalid_delegation_response', 502);
        $require(Contract::keys($data, ['contract', 'issuer', 'delegationId', 'actor', 'subject', 'applicationId', 'clientId', 'organizationId', 'roleId', 'actorRoleId', 'contextVersion', 'operations', 'permissions', 'versions', 'reason', 'ticketReference', 'startedAt', 'expiresAt', 'checkedAt', 'decisionValidUntil']));
        $require($data['contract'] === 'platform-consumer-delegation.v1' && $data['issuer'] === $config->issuer()
            && $data['applicationId'] === $config->applicationId() && $data['clientId'] === $config->clientId()
            && Contract::identifier($data['delegationId']) && $data['contextVersion'] === $session->context_version
            && $data['contextVersion'] === $overlay->context_version && $overlay->source_sid === $session->sid);
        $actor = $data['actor'];
        $subject = $data['subject'];
        $require(is_array($actor) && Contract::keys($actor, ['id', 'name', 'email', 'sourceSessionId', 'assurance'])
            && $actor['id'] === $session->subject && $actor['sourceSessionId'] === $session->sid
            && is_string($actor['name']) && is_string($actor['email']) && is_array($actor['assurance'])
            && Contract::keys($actor['assurance'], ['centralSessionId', 'verifiedAt'])
            && $actor['assurance']['centralSessionId'] === $session->sid && Contract::date($actor['assurance']['verifiedAt']) !== null);
        $require(is_array($subject) && Contract::keys($subject, ['id', 'name', 'email', 'locale', 'classification', 'assurance'])
            && Contract::identifier($subject['id']) && $subject['id'] !== $actor['id'] && is_string($subject['name']) && is_string($subject['email'])
            && in_array($subject['locale'], ['en', 'bg'], true) && $subject['classification'] === 'person' && $subject['assurance'] === null);
        $expected = $overlay->decision;
        $require(is_array($expected) && $subject['id'] === ($expected['subject']['id'] ?? null)
            && $data['organizationId'] === ($expected['organizationId'] ?? null) && $data['roleId'] === ($expected['roleId'] ?? null)
            && $data['actorRoleId'] === ($session->selection['roleId'] ?? null)
            && Contract::strings($data['operations'], true) && count($data['operations']) > 0 && Contract::strings($data['permissions'], true)
            && array_diff($data['operations'], $expected['operations'] ?? []) === [] && is_array($data['versions'])
            && is_string($data['reason']) && is_string($data['ticketReference']));
        if (isset($expected['delegationId'])) {
            $require($data['delegationId'] === $expected['delegationId'] && $data['versions'] === $expected['versions']
                && $data['startedAt'] === $expected['startedAt'] && $data['expiresAt'] === $expected['expiresAt']
                && $data['permissions'] === $expected['permissions']);
        }
        $start = Contract::date($data['startedAt']);
        $end = Contract::date($data['expiresAt']);
        $checked = Contract::date($data['checkedAt']);
        $valid = Contract::date($data['decisionValidUntil']);
        $now = microtime(true);
        $require($start !== null && $end !== null && $checked !== null && $valid !== null
            && $start <= $checked && $checked <= $now + 0.1 && $now - $checked <= 5
            && $end > $now && $end - $start <= 900 && $valid > $now && $valid <= $end && $valid - $checked <= 5);

        return new self($data);
    }

    public function principal(): Principal
    {
        return new Principal(['contract' => $this->data['contract'], 'issuer' => $this->data['issuer'], 'subject' => $this->data['subject']['id'], 'principal_kind' => 'user',
            'permissions' => $this->data['permissions'], 'roles' => [], 'organization_id' => $this->data['organizationId'],
            'assurance' => null, 'central_session_id' => null, 'expires_at' => $this->data['decisionValidUntil'], 'delegation' => $this->data]);
    }
}
