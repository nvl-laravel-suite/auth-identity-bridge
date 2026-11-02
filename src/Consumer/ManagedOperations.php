<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Consumer;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use Illuminate\Http\Request;
use Throwable;

/** Headless managed operations on the existing ConsumerClient transport/session owners.
 * @api
 */
trait ManagedOperations
{
    public function readProfile(Request $request, array $input): ManagedReadResult
    {
        return $this->managedRead($request, 'users.profile.read', $input);
    }

    public function readMetadata(Request $request, array $input): ManagedReadResult
    {
        return $this->managedRead($request, 'users.metadata.read', $input);
    }

    public function updateProfile(Request $request, #[\SensitiveParameter] array $input): ManagedCommandResult
    {
        return $this->managedWrite($request, 'users.profile.update', $input);
    }

    public function updateMetadata(Request $request, #[\SensitiveParameter] array $input): ManagedCommandResult
    {
        return $this->managedWrite($request, 'users.metadata.update', $input);
    }

    public function operationStatus(Request $request, array $reference): ManagedCommandResult
    {
        $actor = null;
        $trusted = null;
        $confirmed = null;
        try {
            $command = $this->commands->original($reference);
            $actor = $this->managedActor($request);
            Contract::require($this->referenceMatches($command->reference, $actor), 'context_changed', 409);
            $trusted = $command->reference;
            if ($command->state === 'committed') {
                $confirmed = ManagedContract::receipt($trusted['operation'], $command->receipt, $trusted);
            }
            $data = $this->exchange($actor, 'operations.status', ['idempotencyKey' => $trusted['idempotencyKey']]);
            $receipt = ManagedContract::status($data, $trusted);
            if ($receipt !== null) {
                return $this->managedCommitted($actor, $trusted, $receipt);
            }
            if ($confirmed !== null) {
                return $this->managedCommitted($actor, $trusted, $confirmed);
            }
            Contract::require($this->managedCurrent($actor), 'context_changed', 409);

            return new ManagedCommandResult('pending', $trusted);
        } catch (Throwable $error) {
            if ($actor && ! $this->managedCurrent($actor)) {
                $error = new IdentityException('context_changed', 409);
            }
            if ($confirmed !== null) {
                // A later policy/MFA refusal cannot uncommit an already verified original receipt.
                return new ManagedCommandResult('committed', $trusted, $confirmed, $this->managedCurrent($actor) ? 'current' : 'changed', 'pending', ManagedFailure::from($error));
            }

            // Refused status is not evidence that the original remote command failed.
            return new ManagedCommandResult('unknown', $trusted, error: ManagedFailure::from($error));
        }
    }

    private function managedRead(Request $request, string $operation, array $input): ManagedReadResult
    {
        $actor = null;
        try {
            $input = ManagedContract::input($operation, $input);
            $actor = $this->managedActor($request);
            $data = ManagedContract::read($operation, $this->exchange($actor, $operation, $input), $input);
            Contract::require($this->managedCurrent($actor), 'context_changed', 409);

            return new ManagedReadResult('read', $data);
        } catch (Throwable $error) {
            if ($actor && ! $this->managedCurrent($actor)) {
                $error = new IdentityException('context_changed', 409);
            }

            return new ManagedReadResult('failed', error: ManagedFailure::from($error));
        }
    }

    private function managedWrite(Request $request, string $operation, #[\SensitiveParameter] array $input): ManagedCommandResult
    {
        $request->attributes->remove('identity.delegation.check');
        $request->attributes->remove('identity.consumer.option_reads');
        $actor = null;
        $reference = null;
        $sent = false;
        try {
            $input = ManagedContract::input($operation, $input);
            $actor = $this->managedActor($request);
            $fields = array_keys($input['changes']);
            sort($fields, SORT_STRING);
            $reference = ['contract' => 'platform-consumer-command-reference.v1', 'bindingHash' => $this->config->bindingHash(), 'issuer' => $this->config->issuer(), 'applicationId' => $this->config->applicationId(), 'clientId' => $this->config->clientId(),
                'localSessionId' => $actor->id, 'subject' => $actor->subject, 'centralSessionId' => $actor->sid, 'organizationId' => $actor->selection['organizationId'] ?? null, 'roleId' => $actor->selection['roleId'] ?? null, 'contextVersion' => $actor->context_version,
                'operation' => $operation, 'userId' => $input['userId'], 'expectedVersion' => $input['expectedVersion'], 'idempotencyKey' => $input['idempotencyKey'], 'changedFields' => $fields];
            try {
                $command = $this->commands->retain($reference);
            } catch (Throwable $error) {
                throw $error instanceof IdentityException && $error->errorCode === 'idempotency_conflict' ? $error : new IdentityException('recovery_unavailable', 503);
            }
            Contract::require($this->managedCurrent($actor), 'context_changed', 409);
            if (! $command->wasRecentlyCreated) {
                return $this->operationStatus($request, $reference);
            }
            $sent = true;
            $receipt = ManagedContract::receipt($operation, $this->exchange($actor, $operation, $input), $input);

            return $this->managedCommitted($actor, $reference, $receipt);
        } catch (Throwable $error) {
            $status = ! $sent || ManagedFailure::refused($error) ? 'failed' : 'unknown';
            if ($reference !== null) {
                try {
                    $this->commands->state($reference, $status);
                } catch (Throwable) { /* Retained intent remains safe to reconcile. */
                }
            }
            if ($actor && ! $this->managedCurrent($actor)) {
                $error = new IdentityException('context_changed', 409);
            }

            return new ManagedCommandResult($status, $reference, error: ManagedFailure::from($error));
        }
    }

    private function managedCommitted(IdentitySession $actor, array $reference, array $receipt): ManagedCommandResult
    {
        $current = $this->managedCurrent($actor);
        $refresh = 'pending';
        try {
            $row = $this->commands->committed($reference, $receipt);
            // Refetch authority belongs to configured users.sync, not the browser actor.
            $refresh = $this->commands->refresh($row->id, $current);
        } catch (Throwable) { /* Verified provider commit survives local journal/refresh failure. */
        }
        $current = $current && $this->managedCurrent($actor);
        if (! $current && $refresh === 'refreshed') {
            $refresh = 'pending';
        }

        return new ManagedCommandResult('committed', $reference, $receipt, $current ? 'current' : 'changed', $refresh);
    }

    private function managedActor(Request $request): IdentitySession
    {
        $current = $this->sessions->current($request) ?? throw new IdentityException('sign_in_required', 401);
        $actor = clone $current;
        Contract::require(($actor->selection['selected'] ?? false) === true, 'context_required', 409);
        Contract::require(! $this->overlays->find($actor->id), 'delegation_control_plane_forbidden', 403);
        $version = $request->input('context_version', $request->header('X-Identity-Context-Version'));
        Contract::require(is_scalar($version) && ctype_digit((string) $version) && (int) $version === $actor->context_version, 'context_changed', 409);
        Contract::require(ManagedContract::identifier($actor->id) && ManagedContract::identifier($actor->subject) && ManagedContract::identifier($actor->sid)
            && is_int($actor->context_version) && $actor->context_version >= 0 && $actor->context_version <= 9007199254740991
            && is_int($actor->token_generation) && $actor->token_generation >= 0 && $actor->token_generation <= 9007199254740991
            && $this->sessions->live($actor), 'session_inactive', 401);
        foreach (['organizationId', 'roleId'] as $key) {
            Contract::require(($actor->selection[$key] ?? null) === null || ManagedContract::identifier($actor->selection[$key]), 'context_changed', 409);
        }
        $tokens = $this->vault->open($actor->token_vault, 'session:'.$actor->id);
        Contract::require(is_string($tokens['access_token'] ?? null) && $tokens['access_token'] !== '' && strlen($tokens['access_token']) <= 32768 && ! preg_match('/[\x00-\x20\x7f]/', $tokens['access_token'])
            && is_int($tokens['expires_at'] ?? null) && $tokens['expires_at'] > now()->timestamp, 'token_inactive', 401);

        return $actor;
    }

    private function managedCurrent(IdentitySession $actor): bool
    {
        try {
            $current = $this->rows->find($actor->id);
            $tokens = $this->vault->open($actor->token_vault, 'session:'.$actor->id);

            return $current !== null && $current->subject === $actor->subject && $current->sid === $actor->sid && $current->selection === $actor->selection
                && $current->context_version === $actor->context_version && $current->token_generation === $actor->token_generation && $current->token_vault === $actor->token_vault
                && $this->sessions->live($current) && ($tokens['expires_at'] ?? 0) > now()->timestamp && ! $this->overlays->find($actor->id);
        } catch (Throwable) {
            return false;
        }
    }

    private function referenceMatches(array $reference, IdentitySession $actor): bool
    {
        return $reference['localSessionId'] === $actor->id && $reference['subject'] === $actor->subject && $reference['centralSessionId'] === $actor->sid
            && $reference['organizationId'] === ($actor->selection['organizationId'] ?? null) && $reference['roleId'] === ($actor->selection['roleId'] ?? null) && $reference['contextVersion'] === $actor->context_version;
    }
}
