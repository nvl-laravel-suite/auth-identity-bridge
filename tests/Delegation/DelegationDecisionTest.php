<?php

namespace IdentityPlatform\Laravel\Tests\Delegation;

use IdentityPlatform\Laravel\Delegation\DelegationDecision;
use IdentityPlatform\Laravel\Delegation\IdentityDelegation;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Tests\Support\NativeJsonOrder;
use IdentityPlatform\Laravel\Tests\TestCase;

class DelegationDecisionTest extends TestCase
{
    private function decision(): array
    {
        return ['contract' => 'platform-consumer-delegation.v1', 'issuer' => 'https://identity.test/api/auth', 'delegationId' => 'mode-1',
            'actor' => ['id' => 'operator-1', 'name' => 'Operator', 'email' => 'operator@example.test', 'sourceSessionId' => 'sid-1', 'assurance' => ['centralSessionId' => 'sid-1', 'verifiedAt' => gmdate('Y-m-d\TH:i:s\Z')]],
            'subject' => ['id' => 'subject-1', 'name' => 'Subject', 'email' => 'subject@example.test', 'locale' => 'en', 'classification' => 'person', 'assurance' => null],
            'applicationId' => 'app-1', 'clientId' => 'web-1', 'organizationId' => null, 'roleId' => null, 'actorRoleId' => null, 'contextVersion' => 3,
            'operations' => ['documents.update'], 'permissions' => ['documents.update'], 'versions' => ['authority' => 1], 'reason' => 'Investigate support case', 'ticketReference' => 'CASE-1',
            'startedAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 1), 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 300), 'checkedAt' => gmdate('Y-m-d\TH:i:s\Z'), 'decisionValidUntil' => gmdate('Y-m-d\TH:i:s\Z', time() + 4)];
    }

    private function validate(array $data): DelegationDecision
    {
        $row = new IdentitySession(['subject' => 'operator-1', 'sid' => 'sid-1', 'selection' => ['selected' => true], 'context_version' => 3]);
        $overlay = new IdentityDelegation(['source_sid' => 'sid-1', 'context_version' => 3, 'decision' => ['subject' => ['id' => 'subject-1'], 'organizationId' => null, 'roleId' => null, 'operations' => ['documents.update']]]);

        return DelegationDecision::validate($data, $row, $overlay, app(IdentityConfig::class));
    }

    public function test_effective_subject_retains_actor_without_inheriting_mfa(): void
    {
        $decision = $this->validate($this->decision());
        self::assertSame('subject-1', $decision->principal()->subject());
        self::assertSame('operator-1', $decision->data['actor']['id']);
        self::assertFalse($decision->principal()->recentMfa());
        self::assertTrue($decision->principal()->hasPermission('documents.update'));
    }

    public function test_wrong_source_session_is_refused(): void
    {
        $data = $this->decision();
        $data['actor']['sourceSessionId'] = 'other-sid';
        $this->expectException(IdentityException::class);
        $this->validate($data);
    }

    public function test_stale_decision_cannot_authorize_a_new_request(): void
    {
        $data = $this->decision();
        $data['checkedAt'] = gmdate('Y-m-d\TH:i:s\Z', time() - 20);
        $this->expectException(IdentityException::class);
        $this->validate($data);
    }

    public function test_subject_assurance_cannot_be_operator_assurance(): void
    {
        $data = $this->decision();
        $data['subject']['assurance'] = $data['actor']['assurance'];
        $this->expectException(IdentityException::class);
        $this->validate($data);
    }

    public function test_redeemed_versions_match_after_native_json_reordering(): void
    {
        $data = [...$this->decision(), 'versions' => ['authority' => 1, 'policy' => 2]];
        $row = new IdentitySession(['subject' => 'operator-1', 'sid' => 'sid-1', 'selection' => ['selected' => true], 'context_version' => 3]);
        $stored = NativeJsonOrder::normalize(DelegationDecision::validate($data, $row, new IdentityDelegation(['source_sid' => 'sid-1', 'context_version' => 3, 'decision' => ['subject' => ['id' => 'subject-1'], 'organizationId' => null, 'roleId' => null, 'operations' => ['documents.update']]]), app(IdentityConfig::class))->data);
        self::assertSame(['policy', 'authority'], array_keys($stored['versions']));
        $overlay = new IdentityDelegation(['source_sid' => 'sid-1', 'context_version' => 3, 'decision' => $stored]);

        self::assertSame('mode-1', DelegationDecision::validate($data, $row, $overlay, app(IdentityConfig::class))->data['delegationId']);

        $this->expectExceptionObject(new IdentityException('invalid_delegation_response', 502));
        DelegationDecision::validate([...$data, 'versions' => ['authority' => 1, 'policy' => 3]], $row, $overlay, app(IdentityConfig::class));
    }
}
