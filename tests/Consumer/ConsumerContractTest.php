<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Consumer;

use IdentityPlatform\Laravel\Consumer\ConsumerContract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Tests\Sync\ProfileFixture;
use IdentityPlatform\Laravel\Tests\TestCase;

class ConsumerContractTest extends TestCase
{
    private function row(?string $organization = null): IdentitySession
    {
        return new IdentitySession(['subject' => 'person-1', 'sid' => 'sid-1', 'selection' => ['selected' => true, ...($organization ? ['organizationId' => $organization] : [])]]);
    }

    public function test_role_options_resolve_off_page_selections_and_reject_partial_or_unrequested_resolution(): void
    {
        $item = ['value' => 'role-1', 'label' => 'Reader', 'hint' => 'reader'];
        $selected = ['value' => 'role-2', 'state' => 'editable', 'label' => 'Reader', 'hint' => 'second-reader'];
        $page = ['items' => [$item], 'nextCursor' => null, 'selected' => [$selected]];
        $input = ['selectedValues' => ['role-2']];
        $this->validate('roles.options.query', $page, $input);
        $this->validate('roles.options.query', array_replace($page, ['selected' => [['value' => 'role-2', 'state' => 'unavailable']]]), $input);
        $this->denied('roles.options.query', array_replace($page, ['selected' => []]), $input);
        $this->denied('roles.options.query', array_replace($page, ['selected' => [array_replace($selected, ['value' => 'foreign'])]]), $input);
        $this->denied('roles.options.query', array_replace($page, ['selected' => [array_replace($selected, ['state' => 'unavailable'])]]), $input);
        $this->denied('roles.options.query', array_replace($page, ['items' => [$item, $item]]), $input);
        $this->denied('roles.options.query', array_replace($page, ['nextCursor' => 'https://foreign.test']), $input);
        $this->denied('roles.options.query', array_replace($page, ['items' => array_map(fn ($index) => array_replace($item, ['value' => 'role-'.$index]), range(1, 26))]), $input);
    }

    public function test_permission_options_preserve_rule_keys_without_returning_unbounded_catalogs(): void
    {
        $page = ['items' => [['value' => 'documents.read', 'label' => 'documents.read', 'hint' => 'Read records']], 'nextCursor' => null, 'selected' => [['value' => 'documents.update', 'state' => 'editable', 'label' => 'documents.update', 'hint' => '']]];
        $input = ['selectedValues' => ['documents.update']];
        $this->validate('permissions.options.query', $page, $input);
        $invalid = $page;
        $invalid['items'][0]['value'] = 'Invalid permission';
        $this->denied('permissions.options.query', $invalid, $input);
        $invalid = $page;
        $invalid['selected'][0]['label'] = 'Another key';
        $this->denied('permissions.options.query', $invalid, $input);
    }

    private function profile(): array
    {
        return [...ProfileFixture::consumer(['name' => 'Synthetic person', 'email' => 'person@example.test', 'locale' => 'en']), 'id' => 'person-1', 'version' => 2];
    }

    private function person(): array
    {
        return [...$this->profile(), 'active' => true, 'status' => 'active', 'grantVersion' => 3];
    }

    private function invitation(?string $organization = null): array
    {
        return ['id' => 'invitation-1', 'email' => 'invitee@example.test', 'applicationId' => 'app-1', 'applicationName' => 'Synthetic app', 'organizationId' => $organization, 'organizationName' => $organization ? 'Synthetic organization' : null, 'membershipRole' => $organization ? 'member' : null, 'roles' => [['id' => 'reader-role', 'name' => 'Reader']], 'metadata' => [], 'version' => 2, 'status' => 'pending', 'createdAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 60), 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 3600)];
    }

    private function validate(string $operation, array $data, array $input = [], ?IdentitySession $row = null): void
    {
        ConsumerContract::validate($operation, $data, $input, $row ?? $this->row(), app(IdentityConfig::class));
    }

    private function denied(string $operation, array $data, array $input = [], ?IdentitySession $row = null): void
    {
        try {
            $this->validate($operation, $data, $input, $row);
            self::fail('Malformed or foreign consumer response was accepted: '.$operation);
        } catch (IdentityException $error) {
            self::assertSame('invalid_consumer_response', $error->errorCode);
            self::assertSame(502, $error->status);
        }
    }

    public function test_profile_binds_owner_and_revision_and_rejects_malformed_fields(): void
    {
        $this->validate('profile.read', $this->profile());
        $this->validate('profile.update', $this->profile(), ['expectedVersion' => 1]);
        foreach ([['id' => 'foreign'], ['version' => 0], ['version' => '2'], ['email' => 'invalid'], ['locale' => 'xx'], ['name' => []], ['token' => 'unrequested']] as $change) {
            $this->denied('profile.read', array_replace($this->profile(), $change));
        }
        $this->denied('profile.update', $this->profile(), ['expectedVersion' => 2]);
    }

    public function test_rich_self_profile_rejects_governance_and_invalid_shared_fields(): void
    {
        $rich = array_replace($this->profile(), ['phone' => '+359888123456', 'organizationName' => 'Example', 'position' => 'Engineer', 'bio' => "First line\nSecond line", 'dateOfBirth' => '2000-02-29', 'gender' => 'other', 'country' => 'BG', 'socialLinks' => ['site' => 'https://example.test/me'], 'profileCompleted' => true]);
        $this->validate('profile.read', $rich);
        $this->validate('profile.update', $rich, ['expectedVersion' => 1]);
        foreach ([['timezone' => '+02:00'], ['accountType' => 'admin'], ['dateOfBirth' => '2001-02-29'], ['country' => 'ZZ'], ['socialLinks' => ['site' => 'http://example.test']], ['profileCompleted' => 'true'], ['phone' => str_repeat('x', 33)], ['adminNotes' => 'private'], ['tags' => []], ['lastLoginAt' => null], ['lastLoginIp' => '192.0.2.1']] as $change) {
            $this->denied('profile.read', array_replace($rich, $change));
        }
        unset($rich['phone']);
        $this->denied('profile.read', $rich);
    }

    public function test_directory_is_bounded_and_binds_target_assignments_and_cursor(): void
    {
        $page = ['items' => [$this->person()], 'nextCursor' => null];
        $this->validate('directory.query', $page);
        $this->validate('directory.query', array_replace($page, ['nextCursor' => 'person-1']), ['limit' => 1]);
        $this->denied('directory.query', ['items' => [$this->person(), array_replace($this->person(), ['id' => 'person-2'])], 'nextCursor' => null], ['limit' => 1]);
        $this->denied('directory.query', ['items' => [$this->person()], 'nextCursor' => 'foreign']);
        $this->denied('directory.query', ['items' => ['key' => $this->person()], 'nextCursor' => null]);
        $this->denied('directory.query', ['items' => [array_replace($this->person(), ['active' => 'true'])], 'nextCursor' => null]);
        $detail = [...$this->person(), 'roles' => ['role-1'], 'allow' => ['documents.read'], 'deny' => []];
        $this->validate('directory.read', $detail, ['userId' => 'person-1']);
        $this->validate('access.read', $detail, ['userId' => 'person-1']);
        $this->denied('access.read', $detail, ['userId' => 'foreign']);
        $this->denied('access.read', array_replace($detail, ['deny' => ['documents.read']]), ['userId' => 'person-1']);
        $this->denied('directory.read', array_replace($detail, ['roles' => ['role-1', 'role-1']]), ['userId' => 'person-1']);
    }

    public function test_roles_and_saves_reject_invalid_permissions_and_foreign_targets(): void
    {
        $catalog = ['version' => 4, 'roles' => [['id' => 'role-1', 'key' => 'reader', 'name' => 'Reader', 'protected' => false, 'permissions' => ['documents.read']]], 'permissions' => [['key' => 'documents.read', 'description' => 'Read documents']]];
        $this->validate('roles.query', $catalog);
        $this->denied('roles.query', array_replace($catalog, ['version' => 0]));
        $this->denied('roles.query', array_replace($catalog, ['permissions' => [['key' => 'Invalid permission', 'description' => 'Bad']]]));
        $this->denied('roles.query', array_replace($catalog, ['roles' => [array_replace($catalog['roles'][0], ['protected' => 'false'])]]));
        $this->denied('roles.query', array_replace($catalog, ['permissions' => []]));
        $this->validate('roles.save', ['id' => 'role-1', 'version' => 5], ['expectedVersion' => 4]);
        $this->validate('access.save', ['id' => 'person-1', 'version' => 4], ['userId' => 'person-1', 'expectedVersion' => 3]);
        $this->denied('roles.save', ['id' => 'role-1', 'version' => 4], ['expectedVersion' => 4]);
        $this->denied('access.save', ['id' => 'foreign', 'version' => 4], ['userId' => 'person-1', 'expectedVersion' => 3]);
    }

    public function test_invitations_bind_app_organization_dates_roles_and_mutation_target(): void
    {
        $invite = $this->invitation('org-1');
        $this->validate('invitations.query', ['items' => [$invite], 'nextCursor' => null], [], $this->row('org-1'));
        foreach ([['applicationId' => 'foreign'], ['organizationId' => 'foreign'], ['version' => 0], ['status' => 'unknown'], ['createdAt' => '2026-02-31T00:00:00Z'], ['expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 1)], ['roles' => [['id' => 'role-1', 'name' => []]]], ['metadata' => ['nested' => []]]] as $change) {
            $this->denied('invitations.query', ['items' => [array_replace($invite, $change)], 'nextCursor' => null], [], $this->row('org-1'));
        }
        $mutation = ['id' => 'invitation-1', 'invitation' => $invite];
        $this->validate('invitations.resend', $mutation, ['invitationId' => 'invitation-1', 'expectedVersion' => 1], $this->row('org-1'));
        $this->denied('invitations.resend', $mutation, ['invitationId' => 'foreign', 'expectedVersion' => 1], $this->row('org-1'));
        $this->denied('invitations.resend', array_replace($mutation, ['id' => 'foreign']), ['invitationId' => 'invitation-1', 'expectedVersion' => 1], $this->row('org-1'));
        $created = ['id' => 'invitation-1', 'invitation' => array_replace($this->invitation(), ['version' => 1])];
        $this->validate('invitations.create', $created, ['email' => 'invitee@example.test', 'roles' => ['reader-role']]);
        $this->denied('invitations.create', $created, ['email' => 'other@example.test', 'roles' => ['reader-role']]);
        $this->validate('invitations.revoke', ['id' => 'invitation-1', 'invitation' => array_replace($this->invitation(), ['status' => 'revoked'])], ['invitationId' => 'invitation-1', 'expectedVersion' => 1]);
    }

    public function test_operation_status_accepts_only_known_mutation_results(): void
    {
        $this->validate('operations.status', ['operation' => 'profile.update', 'status' => 'pending', 'data' => null]);
        $this->validate('operations.status', ['operation' => 'profile.update', 'status' => 'completed', 'data' => $this->profile()]);
        $this->validate('operations.status', ['operation' => 'access.save', 'status' => 'completed', 'data' => ['id' => 'app-person', 'version' => 2]]);
        $this->denied('operations.status', ['operation' => 'admin.user.create', 'status' => 'completed', 'data' => []]);
        $this->denied('operations.status', ['operation' => 'profile.update', 'status' => 'pending', 'data' => $this->profile()]);
        $this->denied('operations.status', ['operation' => 'profile.update', 'status' => 'completed', 'data' => array_replace($this->profile(), ['id' => 'foreign'])]);
        $this->denied('operations.status', ['operation' => 'operations.status', 'status' => 'completed', 'data' => []]);
    }

    public function test_step_up_start_requires_exact_pinned_url_purpose_and_short_deadline(): void
    {
        $data = ['id' => 'proof-1', 'authorizationUrl' => 'https://identity.test/consumer/step-up?id=proof-1', 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 60), 'purpose' => 'management'];
        $this->validate('step-up.start', $data, ['purpose' => 'management']);
        foreach ([['authorizationUrl' => 'https://identity.test.evil.test/consumer/step-up?id=proof-1'], ['authorizationUrl' => 'https://identity.test/consumer/step-up?id=proof-2'], ['authorizationUrl' => 'https://identity.test/consumer/step-up?id=proof-1&next=other'], ['purpose' => 'password'], ['expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 301)], ['expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 1)]] as $change) {
            $this->denied('step-up.start', array_replace($data, $change), ['purpose' => 'management']);
        }
    }

    public function test_step_up_redeem_rejects_foreign_or_stale_assurance(): void
    {
        $data = ['purpose' => 'delegation', 'centralSessionId' => 'sid-1', 'verifiedAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 10), 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 290)];
        $this->validate('step-up.redeem', $data, ['purpose' => 'delegation']);
        foreach ([['centralSessionId' => 'other-sid'], ['purpose' => 'password'], ['verifiedAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 1)], ['verifiedAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 301)], ['expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 400)]] as $change) {
            $this->denied('step-up.redeem', array_replace($data, $change), ['purpose' => 'delegation']);
        }
    }

    public function test_delegation_options_bind_context_and_typed_finite_operations(): void
    {
        $data = ['policyVersion' => 1, 'authorityVersion' => 2, 'operations' => [['key' => 'documents.update', 'permissions' => ['documents.update'], 'write' => true]], 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 3600), 'organizationId' => 'org-1'];
        $this->validate('delegation.options', $data, [], $this->row('org-1'));
        foreach ([['organizationId' => null], ['policyVersion' => 0], ['authorityVersion' => '2'], ['operations' => [['key' => 'documents.update', 'permissions' => ['documents.update'], 'write' => 'true']]], ['expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 1)]] as $change) {
            $this->denied('delegation.options', array_replace($data, $change), [], $this->row('org-1'));
        }
        $this->validate('delegation.check', ['dedicated' => 'validator-owns-this']);
        $this->denied('unknown.operation', []);
    }

    public function test_missing_and_nested_malformed_fields_fail_as_sanitized_contract_errors(): void
    {
        $profile = $this->profile();
        unset($profile['locale']);
        $this->denied('profile.read', $profile);
        $this->denied('roles.query', ['version' => 1, 'roles' => [false], 'permissions' => []]);
        $this->denied('invitations.resend', ['id' => 'invitation-1', 'invitation' => 'unsafe'], ['invitationId' => 'invitation-1', 'expectedVersion' => 1]);
        $this->denied('operations.status', ['operation' => 'profile.update', 'status' => 'completed', 'data' => true]);
        $this->denied('directory.query', ['items' => [], 'nextCursor' => 'foreign']);
        $this->denied('delegation.options', ['policyVersion' => 1, 'authorityVersion' => 1, 'operations' => [], 'organizationId' => null, 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 60)]);
    }

    public function test_completed_invitation_status_remains_a_historical_fact_after_its_pending_deadline(): void
    {
        $invitation = array_replace($this->invitation('org-1'), ['createdAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 3 * 86400), 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 86400)]);
        $result = ['id' => 'invitation-1', 'invitation' => $invitation];
        foreach (['invitations.create', 'invitations.resend'] as $operation) {
            $error = null;
            try {
                $this->validate('operations.status', ['operation' => $operation, 'status' => 'completed', 'data' => $result], [], $this->row('org-1'));
            } catch (IdentityException $failure) {
                $error = $failure->errorCode;
            }
            self::assertNull($error, 'Completed invitation facts must remain readable after expiry');
        }
        $this->denied('invitations.query', ['items' => [$invitation], 'nextCursor' => null], [], $this->row('org-1'));
        $this->denied('invitations.resend', $result, ['invitationId' => 'invitation-1', 'expectedVersion' => 1], $this->row('org-1'));
        $this->denied('operations.status', ['operation' => 'invitations.create', 'status' => 'completed', 'data' => ['id' => 'invitation-1', 'invitation' => array_replace($invitation, ['applicationId' => 'foreign'])]], [], $this->row('org-1'));
    }

    public function test_completed_step_up_start_status_is_historical_without_becoming_a_live_proof(): void
    {
        $result = ['id' => 'proof-1', 'authorizationUrl' => 'https://identity.test/consumer/step-up?id=proof-1', 'purpose' => 'management', 'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', time() - 3600)];
        $error = null;
        try {
            $this->validate('operations.status', ['operation' => 'step-up.start', 'status' => 'completed', 'data' => $result]);
        } catch (IdentityException $failure) {
            $error = $failure->errorCode;
        }
        self::assertNull($error, 'Completed step-up initiation facts must remain readable after expiry');
        $this->denied('step-up.start', $result, ['purpose' => 'management']);
        $this->denied('operations.status', ['operation' => 'step-up.start', 'status' => 'completed', 'data' => array_replace($result, ['authorizationUrl' => 'https://foreign.test/consumer/step-up?id=proof-1'])]);
        $this->denied('operations.status', ['operation' => 'step-up.start', 'status' => 'completed', 'data' => array_replace($result, ['expiresAt' => 'invalid'])]);
    }
}
