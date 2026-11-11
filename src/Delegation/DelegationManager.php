<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Delegation;

use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Events\DelegationStateChanged;
use IdentityPlatform\Laravel\Events\LifecycleNotifications;
use IdentityPlatform\Laravel\Events\LocalSessionEnded;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\LoginRepository;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Throwable;

class DelegationManager
{
    public function __construct(private SessionManager $sessions, private SessionRepository $rows, private OverlayRepository $overlays, private ConsumerClient $client, private LoginRepository $logins, private IdentityVault $vault, private IdentityConfig $config, private LifecycleNotifications $notifications) {}

    public function current(Request $request): ?IdentityDelegation
    {
        $row = $this->sessions->current($request);

        return $row ? $this->overlays->find($row->id) : null;
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function start(Request $request, array $input): string
    {
        $row = $this->requireSession($request);
        $this->requireContext($request, $row);
        if ($this->overlays->find($row->id)) {
            throw new IdentityException('delegation_nested_forbidden', 403);
        }
        $allowed = ['subjectId', 'subjectRoleId', 'operations', 'reason', 'ticketReference', 'expectedPolicyVersion', 'expectedAuthorityVersion'];
        if (array_diff(array_keys($input), $allowed) || ! Contract::identifier($input['subjectId'] ?? null) || $input['subjectId'] === $row->subject || ! Contract::strings($input['operations'] ?? null, true) || $input['operations'] === []) {
            throw new IdentityException('delegation_invalid', 422);
        }
        foreach ($input['operations'] as $operation) {
            $this->registration($operation);
        }
        $binding = $this->random();
        $verifier = $this->random();
        $nextVersion = $row->context_version + 1;
        $callback = $this->config->url('delegation.callback');
        $state = $this->logins->create($request->session()->getId(), ['session_id' => $row->id, 'source_sid' => $row->sid, 'browser_binding' => $binding, 'verifier' => $verifier, 'context_version' => $nextVersion, 'callback' => $callback], 'delegation');
        $handoff = $this->client->call($request, 'delegation.start', [...$input, 'browserBinding' => $binding, 'callbackUrl' => $callback, 'state' => $state, 'codeChallenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='), 'codeChallengeMethod' => 'S256', 'contextVersion' => $nextVersion, 'idempotencyKey' => $this->random()]);
        $end = Contract::date($handoff['expiresAt'] ?? null);
        Contract::require(Contract::keys($handoff, ['handoffId', 'code', 'state', 'callbackUrl', 'expiresAt']) && Contract::identifier($handoff['handoffId']) && $this->secret($handoff['code']) && $handoff['state'] === $state && $handoff['callbackUrl'] === $callback && $end !== null && is_string($handoff['expiresAt']) && $end > microtime(true) && $end <= microtime(true) + 120, 'invalid_delegation_response', 502);
        $row->getConnection()->transaction(function () use ($row, $input, $binding, $nextVersion, $handoff): void {
            if (! $this->rows->publish($row, ['context_version' => $nextVersion, 'snapshot' => null, 'application_context' => null])) {
                throw new IdentityException('context_changed', 409);
            }
            $this->overlays->save($row->id, ['source_sid' => $row->sid, 'status' => 'pending', 'browser_binding' => $binding, 'context_version' => $nextVersion, 'handle_vault' => null,
                'decision' => ['subject' => ['id' => $input['subjectId']], 'organizationId' => $row->selection['organizationId'] ?? null, 'roleId' => $input['subjectRoleId'] ?? null, 'operations' => $input['operations']], 'expires_at' => $handoff['expiresAt']]);
            $this->notifications->afterCommit($row->getConnection(), new DelegationStateChanged($this->config->context()->name(), $row->subject, $input['subjectId'], 'pending', $nextVersion, $handoff['expiresAt']));
        });
        $this->clearRequest($request);

        return $callback.'?'.http_build_query(['code' => $handoff['code'], 'state' => $state], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @param  array<array-key, string>  $callback
     */
    public function redeem(Request $request, #[\SensitiveParameter] array $callback): void
    {
        $intent = $this->logins->consume((string) ($callback['state'] ?? ''), $request->session()->getId(), 'delegation');
        $row = $this->requireSession($request);
        $overlay = $this->overlays->find($row->id) ?? throw new IdentityException('delegation_unavailable', 403);
        if ($overlay->status !== 'pending' || $overlay->expires_at->isPast() || $overlay->source_sid !== $row->sid || $intent['session_id'] !== $row->id || $intent['source_sid'] !== $row->sid || $intent['context_version'] !== $row->context_version || $overlay->context_version !== $row->context_version || $intent['browser_binding'] !== $overlay->browser_binding) {
            throw new IdentityException('delegation_binding_changed', 409);
        }
        $result = $this->client->call($this->withContext($request, $row->context_version), 'delegation.redeem', ['code' => $callback['code'] ?? '', 'codeVerifier' => $intent['verifier'], 'state' => $callback['state'], 'browserBinding' => $overlay->browser_binding, 'callbackUrl' => $intent['callback'], 'contextVersion' => $row->context_version]);
        Contract::require(Contract::keys($result, ['handle', 'decision']) && $this->secret($result['handle']) && is_array($result['decision']), 'invalid_delegation_response', 502);
        $decision = DelegationDecision::validate($result['decision'], $row, $overlay, $this->config);
        $this->requireLocalDeadline($decision, $row);
        $row->getConnection()->transaction(function () use ($row, $overlay, $result, $decision): void {
            $locked = $this->overlays->find($row->id, true);
            $locked = $this->assertCurrent($row, $locked, true);
            if ($locked->status !== 'pending' || $locked->browser_binding !== $overlay->browser_binding || $locked->expires_at->isPast()) {
                throw new IdentityException('delegation_binding_changed', 409);
            }
            $this->overlays->save($row->id, ['status' => 'active', 'decision' => $decision->data, 'handle_vault' => $this->vault->seal(['handle' => $result['handle']], 'delegation:'.$row->id), 'expires_at' => $decision->data['expiresAt']]);
            $this->notifications->afterCommit($row->getConnection(), new DelegationStateChanged($this->config->context()->name(), $row->subject, $decision->data['subject']['id'], 'active', $row->context_version, $decision->data['expiresAt']));
        });
        $this->clearRequest($request);
    }

    public function check(Request $request, string $operation): DelegationDecision
    {
        $this->registration($operation);
        $row = $this->requireSession($request);
        if (! in_array($request->method(), ['GET', 'HEAD'], true)) {
            $this->requireContext($request, $row);
        }
        $overlay = $this->overlays->find($row->id) ?? throw new IdentityException('delegation_unavailable', 403);
        $handleVault = $overlay->handle_vault;
        if ($overlay->status !== 'active' || ! $handleVault || $overlay->expires_at->isPast()) {
            throw new IdentityException('delegation_unavailable', 403);
        }
        $this->assertCurrent($row, $overlay);
        $binding = hash('sha256', json_encode([spl_object_id($request), $request->method(), $operation, $this->config->bindingHash(),
            $row->id, $row->user_id, $row->subject, $row->sid, $row->context_version, $row->token_generation, $row->selection,
            $overlay->id, $overlay->source_sid, $overlay->context_version, $overlay->browser_binding, $overlay->decision,
            hash('sha256', $handleVault), $overlay->expires_at->toIso8601String()], JSON_THROW_ON_ERROR));
        $retained = $request->attributes->get('identity.delegation.check');
        $request->attributes->remove('identity.delegation.check');
        $decision = null;
        if (is_array($retained) && ($retained['binding'] ?? null) === $binding && ($retained['decision'] ?? null) instanceof DelegationDecision) {
            try {
                $decision = DelegationDecision::validate($retained['decision']->data, $row, $overlay, $this->config);
            } catch (IdentityException) { /* Expired request proof requires another authoritative check. */
            }
        }
        if (! $decision) {
            $data = $this->client->call($request, 'delegation.check', [...$this->proof($overlay), 'operation' => $operation]);
            $decision = DelegationDecision::validate($data, $row, $overlay, $this->config);
        }
        $this->requireLocalDeadline($decision, $row);
        Contract::require(in_array($operation, $decision->data['operations'], true), 'delegation_operation_forbidden', 403);
        $this->assertCurrent($row, $this->overlays->find($row->id));
        $request->attributes->set('identity.delegation.check', ['binding' => $binding, 'decision' => $decision]);
        $request->attributes->set('identity.delegation', $decision);
        $request->attributes->set('identity.principal', $decision->principal());
        $request->attributes->set('identity.principal.fresh', true);
        Auth::forgetGuards();

        return $decision;
    }

    public function stop(Request $request): void
    {
        $row = $this->requireSession($request);
        $overlay = $this->overlays->find($row->id);
        if (! $overlay) {
            return;
        }
        $version = $request->input('context_version', $request->header('X-Identity-Context-Version'));
        if (! is_scalar($version) || ! ctype_digit((string) $version) || ! in_array((int) $version, [$row->context_version, $overlay->context_version], true)) {
            throw new IdentityException('context_changed', 409);
        }
        $proof = $overlay->handle_vault ? $this->proof($overlay) : null;
        $row->getConnection()->transaction(function () use ($row, $overlay): void {
            $locked = $this->overlays->find($row->id, true);
            $current = $this->rows->find($row->id, true);
            if (! $locked || ! $current || $locked->source_sid !== $row->sid || $current->sid !== $row->sid || $current->subject !== $row->subject || $current->context_version !== $row->context_version || $current->token_generation !== $row->token_generation || $locked->context_version !== $overlay->context_version || $locked->handle_vault !== $overlay->handle_vault) {
                throw new IdentityException('context_changed', 409);
            }
            $this->overlays->stop($row->id);
            if (! $this->rows->publish($row, ['context_version' => $row->context_version + 1, 'snapshot' => null, 'application_context' => null])) {
                throw new IdentityException('context_changed', 409);
            }
            $this->notifications->afterCommit($row->getConnection(), new DelegationStateChanged($this->config->context()->name(), $row->subject, null, 'stopped', $row->context_version + 1, null));
        });
        $this->clearRequest($request);
        if ($proof) {
            try {
                $this->client->call($this->withContext($request, $row->context_version + 1), 'delegation.stop', $proof);
            } catch (Throwable) {
                // Local retirement is authoritative even when the provider is unavailable.
            }
        }
        try {
            $this->sessions->principal($request, true);
        } catch (Throwable) {
            if ($this->rows->delete($row->id)) {
                $this->notifications->afterCommit($row->getConnection(), new LocalSessionEnded($this->config->context()->name(), $row->subject, $row->context_version + 1));
            }
            $request->session()->forget('identity.session');
        }
    }

    /**
     * @return array{handle: mixed, browserBinding: string, contextVersion: int}
     */
    public function proof(IdentityDelegation $overlay): array
    {
        if ($overlay->handle_vault === null) {
            throw new IdentityException('delegation_unavailable', 403);
        }
        $handle = $this->vault->open($overlay->handle_vault, 'delegation:'.$overlay->id);

        return ['handle' => $handle['handle'], 'browserBinding' => $overlay->browser_binding, 'contextVersion' => $overlay->context_version];
    }

    /**
     * @return array{write: bool, resource_type: non-empty-string, ...}
     */
    public function registration(string $operation): array
    {
        $registration = $this->config->value('delegation.operations', [])[$operation] ?? null;
        if (! is_array($registration) || preg_match('/(?:^|\.)(?:security|credentials?|roles?|grants?|clients?|invitations?|global|admin|impersonat|delegat)(?:\.|$)/i', $operation)) {
            throw new IdentityException('delegation_operation_forbidden', 403);
        }

        return $registration;
    }

    /**
     * @return IdentityDelegation The same overlay, after source and liveness fences.
     */
    public function assertCurrent(IdentitySession $expected, ?IdentityDelegation $overlay, bool $lockSession = false): IdentityDelegation
    {
        $current = $this->rows->find($expected->id, $lockSession);
        if (! $current || ! $overlay || $current->sid !== $overlay->source_sid || $current->sid !== $expected->sid || $current->subject !== $expected->subject || $current->context_version !== $expected->context_version || $current->context_version !== $overlay->context_version || $current->token_generation !== $expected->token_generation || $current->expires_at->isPast() || $current->started_at->addSeconds((int) $this->config->value('local.absolute_seconds', 43200))->isPast() || $current->last_activity_at->addSeconds((int) $this->config->value('local.idle_seconds', 1800))->isPast()) {
            throw new IdentityException('context_changed', 409);
        }

        return $overlay;
    }

    public function requireContext(Request $request, IdentitySession $row): void
    {
        $version = $request->input('context_version', $request->header('X-Identity-Context-Version'));
        if (! is_scalar($version) || ! ctype_digit((string) $version) || (int) $version !== $row->context_version) {
            throw new IdentityException('context_changed', 409);
        }
    }

    private function requireSession(Request $request): IdentitySession
    {
        return $this->sessions->current($request) ?? throw new IdentityException('sign_in_required', 401);
    }

    private function requireLocalDeadline(DelegationDecision $decision, IdentitySession $row): void
    {
        $end = Contract::date($decision->data['expiresAt']);
        if ($end > min($row->expires_at->getTimestamp(), $row->started_at->addSeconds((int) $this->config->value('local.absolute_seconds', 43200))->getTimestamp())) {
            throw new IdentityException('invalid_delegation_response', 502);
        }
    }

    private function random(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
    }

    /** @phpstan-assert-if-true non-empty-string $value */
    private function secret(mixed $value): bool
    {
        return is_string($value) && preg_match('/^[A-Za-z0-9._~-]{32,512}$/D', $value) === 1;
    }

    private function withContext(Request $request, int $version): Request
    {
        $copy = clone $request;
        $copy->request = clone $request->request;
        $copy->query = clone $request->query;
        if ($request->isJson()) {
            $copy->setJson(clone $request->json());
        }
        $copy->merge(['context_version' => $version]);

        return $copy;
    }

    private function clearRequest(Request $request): void
    {
        foreach (['identity.delegation', 'identity.delegation.check', 'identity.principal', 'identity.principal.fresh'] as $attribute) {
            $request->attributes->remove($attribute);
        }
        Auth::forgetGuards();
    }
}
