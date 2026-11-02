<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use Closure;
use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Throwable;

/** A synchronous app mutation and its immutable audit/outbox share the consumer connection.
 * @api
 */
class DelegatedActionRunner
{
    public function __construct(private DelegationManager $delegations, private SessionManager $sessions, private OverlayRepository $overlays, private DelegatedActionRepository $actions, private ConsumerClient $client, private IdentityVault $vault, private IdentityConfig $config) {}

    public function run(Request $request, string $operation, string $resourceType, string $resourceId, array $command, string $idempotencyKey, Closure $lockResource, Closure $mutate): array
    {
        $registration = $this->delegations->registration($operation);
        Contract::require($registration['write'] && $registration['resource_type'] === $resourceType && $resourceId !== '' && strlen($resourceId) <= 256 && preg_match('/^[A-Za-z0-9._~-]{32,512}$/D', $idempotencyKey) === 1, 'delegation_operation_forbidden', 403);
        $decision = $this->delegations->check($request, $operation);
        $row = $this->sessions->current($request) ?? throw new IdentityException('sign_in_required', 401);
        $overlay = $this->overlays->find($row->id) ?? throw new IdentityException('delegation_unavailable', 403);
        $digest = hash('sha256', json_encode($this->canonical(['delegationId' => $decision->data['delegationId'], 'subjectId' => $decision->data['subject']['id'], 'organizationId' => $decision->data['organizationId'], 'operation' => $operation, 'resourceType' => $resourceType, 'resourceId' => $resourceId, 'command' => $command]), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        $id = hash('sha256', $this->config->bindingHash()."\0".$decision->data['delegationId']."\0".$idempotencyKey);
        if ($existing = $this->actions->find($id)) {
            return $this->replay($existing, $digest);
        }
        $admissionStarted = hrtime(true);
        $receipt = $this->client->call($request, 'delegation.admit', [...$this->delegations->proof($overlay), 'operation' => $operation, 'organizationId' => $decision->data['organizationId'], 'resourceType' => $resourceType, 'resourceId' => $resourceId, 'commandDigest' => $digest, 'idempotencyKey' => $idempotencyKey]);
        $this->validateReceipt($receipt, $row, $overlay, $operation, $resourceType, $resourceId, $digest, $idempotencyKey);
        $admissionDeadline = $admissionStarted + (int) floor((Contract::date($receipt['expiresAt']) - Contract::date($receipt['admittedAt'])) * 1_000_000_000);
        $audit = ['actor_id' => $decision->data['actor']['id'], 'actor_name' => $decision->data['actor']['name'], 'subject_id' => $decision->data['subject']['id'], 'subject_name' => $decision->data['subject']['name'], 'organization_id' => $decision->data['organizationId'], 'source_sid' => $row->sid, 'versions' => $decision->data['versions'], 'reason' => $decision->data['reason'], 'ticket_reference' => $decision->data['ticketReference'], 'admitted_at' => $receipt['admittedAt'], 'reporting_expires_at' => $receipt['reportingExpiresAt']];
        $values = ['id' => $id, 'session_id' => $row->id, 'delegation_id' => $decision->data['delegationId'], 'operation' => $operation, 'command_digest' => $digest,
            'actor_id' => $audit['actor_id'], 'subject_id' => $audit['subject_id'], 'organization_id' => $audit['organization_id'], 'resource_type' => $resourceType, 'resource_id' => $resourceId, 'audit' => $audit,
            'receipt_vault' => $this->vault->seal(array_intersect_key($receipt, array_flip(['receiptId', 'reportingCapability', 'commandDigest'])), 'delegated-action:'.$id)];
        try {
            $result = $this->actions->transaction(function () use ($id, $digest, $row, $overlay, $receipt, $admissionDeadline, $values, $lockResource, $mutate): array {
                if ($existing = $this->actions->find($id, true)) {
                    return $this->replay($existing, $digest);
                }
                $resource = $lockResource();
                $connection = (new IdentityDelegatedAction)->getConnection()->getName();
                if (($resource instanceof Model && $resource->getConnection()->getName() !== $connection) || $connection !== app('db')->connection()->getName()) {
                    throw new IdentityException('delegation_action_connection_mismatch', 503);
                }
                $locked = $this->overlays->find($row->id, true);
                $this->delegations->assertCurrent($row, $locked, true);
                if ($locked->status !== 'active' || $locked->handle_vault !== $overlay->handle_vault || $locked->expires_at->isPast()) {
                    throw new IdentityException('delegation_unavailable', 403);
                }
                $this->requireAdmissionLive($receipt, $admissionDeadline);
                $result = $mutate($resource);
                if (! is_array($result)) {
                    throw new IdentityException('delegation_result_invalid', 500);
                }
                $this->delegations->assertCurrent($row, $this->overlays->find($row->id), true);
                $this->requireAdmissionLive($receipt, $admissionDeadline);
                $this->actions->create([...$values, 'outcome' => 'committed', 'result' => $result]);

                return $result;
            });
        } catch (Throwable $error) {
            $this->actions->transaction(function () use ($id, $values): void {
                if (! $this->actions->find($id, true)) {
                    $this->actions->create([...$values, 'outcome' => 'rejected', 'result' => null]);
                }
            });
            $this->queueReport($id);
            throw $error;
        }
        $request->attributes->set('identity.delegation.admitted', $id);
        $this->queueReport($id);

        return $result;
    }

    private function validateReceipt(array $receipt, IdentitySession $row, IdentityDelegation $overlay, string $operation, string $resourceType, string $resourceId, string $digest, string $idempotencyKey): void
    {
        $required = ['receiptId', 'delegationId', 'contextVersion', 'operation', 'organizationId', 'resourceType', 'resourceId', 'commandDigest', 'idempotencyKey', 'admittedAt', 'expiresAt', 'reportingCapability', 'reportingExpiresAt', 'decision'];
        Contract::require(Contract::keys($receipt, $required) && Contract::identifier($receipt['receiptId']) && $receipt['delegationId'] === $overlay->decision['delegationId'] && $receipt['contextVersion'] === $row->context_version && $receipt['operation'] === $operation && $receipt['organizationId'] === $overlay->decision['organizationId'] && $receipt['resourceType'] === $resourceType && $receipt['resourceId'] === $resourceId && $receipt['commandDigest'] === $digest && $receipt['idempotencyKey'] === $idempotencyKey && is_string($receipt['reportingCapability']) && preg_match('/^[A-Za-z0-9._~-]{32,512}$/D', $receipt['reportingCapability']) === 1 && is_array($receipt['decision']), 'invalid_delegation_admission', 502);
        $decision = DelegationDecision::validate($receipt['decision'], $row, $overlay, $this->config);
        $admitted = Contract::date($receipt['admittedAt']);
        $end = Contract::date($receipt['expiresAt']);
        $reportEnd = Contract::date($receipt['reportingExpiresAt']);
        Contract::require($admitted !== null && $end !== null && $reportEnd !== null && $admitted <= microtime(true) + 0.1 && microtime(true) - $admitted <= 5 && $end > microtime(true) && $end - $admitted <= 5 && $end <= Contract::date($decision->data['expiresAt']) && $reportEnd > microtime(true) && $reportEnd - $admitted <= 7 * 86400 && in_array($operation, $decision->data['operations'], true), 'invalid_delegation_admission', 502);
    }

    private function requireAdmissionLive(array $receipt, int $admissionDeadline): void
    {
        $verified = Contract::date($receipt['decision']['actor']['assurance']['verifiedAt']);
        $now = microtime(true);
        if (hrtime(true) >= $admissionDeadline || Contract::date($receipt['expiresAt']) <= $now || Contract::date($receipt['decision']['decisionValidUntil']) <= $now || Contract::date($receipt['decision']['expiresAt']) <= $now || $verified === null || $verified > $now || $now - $verified > 300) {
            throw new IdentityException('delegation_admission_expired', 409);
        }
    }

    private function replay(IdentityDelegatedAction $action, string $digest): array
    {
        if (! hash_equals($action->command_digest, $digest)) {
            throw new IdentityException('delegation_idempotency_conflict', 409);
        }
        if ($action->outcome !== 'committed') {
            throw new IdentityException('delegation_operation_rejected', 409);
        }

        return $action->result;
    }

    private function canonical(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }
        if (! array_is_list($value)) {
            ksort($value, SORT_STRING);
        }

        return array_map(fn ($item) => $this->canonical($item), $value);
    }

    private function queueReport(string $id): void
    {
        try {
            ReportDelegatedAction::dispatch($id)->afterCommit();
        } catch (Throwable) {
            // The durable unreported row remains available for explicit reconciliation.
        }
    }
}
