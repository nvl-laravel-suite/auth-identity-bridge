<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Consumer;

use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Support\IdentityVault;
use Illuminate\Http\Request;
use LogicException;

/** @api */
class ConsumerClient
{
    use ManagedOperations;

    private const PATHS = [
        'users.profile.read' => 'app/users/profile/read', 'users.profile.update' => 'app/users/profile/update',
        'users.metadata.read' => 'app/users/metadata/read', 'users.metadata.update' => 'app/users/metadata/update',
        'profile.read' => 'self/read', 'profile.update' => 'self/profile',
        'directory.query' => 'app/users/query', 'directory.read' => 'app/users/read',
        'access.read' => 'app/access/read', 'access.save' => 'app/access/save',
        'roles.options.query' => 'app/roles/options', 'permissions.options.query' => 'app/permissions/options',
        'roles.query' => 'app/roles/read', 'roles.save' => 'app/roles/save',
        'invitations.query' => 'app/invitations/query', 'invitations.create' => 'app/invitations/create',
        'invitations.revoke' => 'app/invitations/revoke', 'invitations.resend' => 'app/invitations/resend',
        'operations.status' => 'operations/status', 'step-up.start' => 'step-up/start', 'step-up.redeem' => 'step-up/redeem',
        'delegation.options' => 'delegations/options', 'delegation.start' => 'delegations/start', 'delegation.redeem' => 'delegations/redeem',
        'delegation.check' => 'delegations/check', 'delegation.admit' => 'delegations/authorize-operation', 'delegation.stop' => 'delegations/stop',
    ];

    private const READS = ['users.profile.read', 'users.metadata.read', 'profile.read', 'directory.query', 'directory.read', 'access.read', 'roles.query', 'roles.options.query', 'permissions.options.query', 'invitations.query', 'operations.status', 'delegation.options', 'delegation.check'];

    public function __construct(private SessionManager $sessions, private SessionRepository $rows, private IdentityVault $vault, private IdentityConfig $config, private IdentityHttp $http, private OverlayRepository $overlays, private CommandJournal $commands) {}

    /**
     * @param  array<array-key, mixed>  $input
     * @return array<array-key, mixed>
     */
    public function call(Request $request, string $operation, array $input = []): array
    {
        if (! isset(self::PATHS[$operation])) {
            throw new IdentityException('unknown_consumer_operation', 400);
        }
        if (in_array($operation, ManagedContract::WRITES, true)) {
            return $this->managedWrite($request, $operation, $input)->jsonSerialize();
        }
        if (in_array($operation, ManagedContract::READS, true)) {
            $result = $this->managedRead($request, $operation, $input);
            if ($result->status !== 'read') {
                $error = $result->error ?? throw new LogicException('A failed managed read requires its failure.');
                throw new IdentityException($error->code, $error->httpStatus());
            }

            return $result->data ?? throw new LogicException('A managed read result requires read data.');
        }
        if ($operation === 'operations.status') {
            $input = ManagedContract::input($operation, $input);
        }
        if (! in_array($operation, self::READS, true)) {
            $request->attributes->remove('identity.delegation.check');
            $request->attributes->remove('identity.consumer.option_reads');
        }
        $row = $this->sessions->current($request) ?? throw new IdentityException('sign_in_required', 401);
        if (($row->selection['selected'] ?? false) !== true) {
            throw new IdentityException('context_required', 409);
        }
        if ($this->overlays->find($row->id) && ! in_array($operation, ['delegation.check', 'delegation.redeem', 'delegation.admit', 'delegation.stop'], true)) {
            throw new IdentityException('delegation_control_plane_forbidden', 403);
        }
        if (! in_array($operation, self::READS, true)) {
            $version = $request->input('context_version', $request->header('X-Identity-Context-Version'));
            if (! is_scalar($version) || ! ctype_digit((string) $version) || (int) $version !== $row->context_version) {
                throw new IdentityException('context_changed', 409);
            }
        }
        $optionRead = in_array($operation, ['roles.options.query', 'permissions.options.query'], true);
        $cacheKey = hash('sha256', json_encode([$this->config->bindingHash(), $row->id, $row->subject, $row->sid, $row->context_version, $row->token_generation, $row->selection, $operation, $input], JSON_THROW_ON_ERROR));
        $cached = $request->attributes->get('identity.consumer.option_reads', []);
        $cached = is_array($cached) ? $cached : [];
        $cacheHit = $optionRead && isset($cached[$cacheKey]);
        if ($cacheHit) {
            $data = $cached[$cacheKey];
            Contract::require(is_array($data), 'invalid_consumer_response', 502);
        } else {
            $data = $this->exchange($row, $operation, $input);
            ConsumerContract::validate($operation, $data, $input, $row, $this->config);
            if ($operation === 'operations.status' && in_array($data['operation'] ?? null, ManagedContract::WRITES, true)) {
                Contract::require(ManagedContract::key($input['idempotencyKey'] ?? null), 'validation_failed', 400);
                ManagedContract::status($data, $this->commands->forActor($row, $input['idempotencyKey']));
            }
        }
        $current = $this->rows->find($row->id);
        if (! $current || ! $this->sessions->live($current) || $current->context_version !== $row->context_version || $current->token_generation !== $row->token_generation) {
            throw new IdentityException('context_changed', 409);
        }

        if ($optionRead && ! $cacheHit) {
            if (count($cached) >= 16) {
                array_shift($cached);
            }
            $cached[$cacheKey] = $data;
            $request->attributes->set('identity.consumer.option_reads', $cached);
        }

        return $data;
    }

    /**
     * Shared fixed-origin confidential transport, with exact ordinary actor envelope binding.
     *
     * @param  array<array-key, mixed>  $input
     * @return array<array-key, mixed>
     */
    private function exchange(IdentitySession $row, string $operation, array $input): array
    {
        $tokens = $this->vault->open($row->token_vault, 'session:'.$row->id);
        $selection = array_intersect_key($row->selection, array_flip(['organizationId', 'roleId']));
        $wire = $input;
        if (is_array($wire['changes'] ?? null) && isset($wire['changes']['socialLinks']) && is_array($wire['changes']['socialLinks'])) {
            $wire['changes']['socialLinks'] = (object) $wire['changes']['socialLinks'];
        }
        $preserveKinds = in_array($operation, [...ManagedContract::READS, ...ManagedContract::WRITES, 'operations.status'], true);
        $reply = $this->http->json('/api/consumer/v1/'.self::PATHS[$operation], ['token' => $tokens['access_token'], ...$selection, 'input' => $wire === [] ? (object) [] : $wire], preserveObjectKinds: $preserveKinds);
        Contract::require(Contract::keys($reply, ['contract', 'issuer', 'applicationId', 'clientId', 'subject', 'centralSessionId', 'data'])
            && $reply['contract'] === 'platform-consumer-result.v1' && $reply['issuer'] === $this->config->issuer()
            && $reply['applicationId'] === $this->config->applicationId() && $reply['clientId'] === $this->config->clientId()
            && $reply['subject'] === $row->subject && $reply['centralSessionId'] === $row->sid, 'invalid_consumer_response', 502);

        if ($preserveKinds) {
            Contract::require($reply['data'] instanceof \stdClass, 'invalid_consumer_response', 502);

            return ManagedContract::jsonData($operation, $reply['data']);
        }
        Contract::require(is_array($reply['data']), 'invalid_consumer_response', 502);

        return $reply['data'];
    }

    /**
     * Only an already-admitted action may be reconciled without a browser session.
     *
     * @param  array<array-key, mixed>  $receipt
     * @return array<array-key, mixed>
     */
    public function report(array $receipt, string $outcome, ?string $resultCode = null): array
    {
        Contract::require(in_array($outcome, ['committed', 'rejected'], true), 'invalid_outcome', 400);
        $input = array_intersect_key($receipt, array_flip(['receiptId', 'reportingCapability', 'commandDigest']));
        $input['outcome'] = $outcome;
        if ($resultCode !== null) {
            $input['resultCode'] = $resultCode;
        }
        $reply = $this->http->json('/api/consumer/v1/delegations/complete-operation', ['input' => $input]);
        $data = $reply['data'] ?? null;
        Contract::require(Contract::keys($reply, ['contract', 'issuer', 'clientId', 'data']) && $reply['contract'] === 'platform-consumer-outcome.v1'
            && $reply['issuer'] === $this->config->issuer() && $reply['clientId'] === $this->config->clientId()
            && is_array($data) && ($data['receiptId'] ?? null) === ($receipt['receiptId'] ?? null) && ($data['status'] ?? null) === $outcome, 'invalid_outcome_response', 502);

        return $data;
    }
}
