<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

use Closure;
use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

/** Ordinary local writes serialize their native session fence with mode/context changes.
 * @api
 */
class OrdinaryActionRunner
{
    public function __construct(private SessionManager $sessions, private SessionRepository $rows, private OverlayRepository $overlays, private IdentityConfig $config) {}

    /**
     * @template TResource
     * @template TResult
     *
     * @param  Closure(): TResource  $lockResource
     * @param  Closure(TResource, Principal): TResult  $mutate
     * @return TResult
     */
    public function run(Request $request, Closure $lockResource, Closure $mutate): mixed
    {
        if ($request->isMethodSafe()) {
            throw new IdentityException('ordinary_write_required', 405);
        }
        $row = $this->sessions->current($request) ?? throw new IdentityException('sign_in_required', 401);
        $version = $request->input('context_version', $request->header('X-Identity-Context-Version'));
        if (! is_scalar($version) || ! ctype_digit((string) $version) || (int) $version !== $row->context_version) {
            throw new IdentityException('context_changed', 409);
        }
        $this->requireOrdinary($row->id);
        $principal = $this->sessions->principal($request, true);
        $this->requirePrincipal($principal, $row);
        $connection = $row->getConnection();
        if ($connection->getName() !== app('db')->connection()->getName()) {
            throw new IdentityException('ordinary_action_connection_mismatch', 503);
        }

        return $connection->transaction(function () use ($request, $row, $principal, $lockResource, $mutate, $connection): mixed {
            $resource = $lockResource();
            if ($resource instanceof Model && $resource->getConnection()->getName() !== $connection->getName()) {
                throw new IdentityException('ordinary_action_connection_mismatch', 503);
            }
            $this->assertFence($request, $row, $principal);
            $result = $mutate($resource, $principal);
            $this->assertFence($request, $row, $principal);

            return $result;
        });
    }

    private function assertFence(Request $request, IdentitySession $expected, Principal $principal): void
    {
        $current = $this->rows->find($expected->id, true);
        if (! $current || ! $request->hasSession() || $request->session()->get('identity.session') !== $expected->id
            || $current->subject !== $expected->subject || $current->sid !== $expected->sid || $current->user_id !== $expected->user_id
            || $current->context_version !== $expected->context_version || $current->token_generation !== $expected->token_generation
            || $current->selection !== $expected->selection || $current->expires_at->isPast()
            || $current->started_at->addSeconds((int) $this->config->value('local.absolute_seconds', 43200))->isPast()
            || $current->last_activity_at->addSeconds((int) $this->config->value('local.idle_seconds', 1800))->isPast()) {
            throw new IdentityException('context_changed', 409);
        }
        $this->requireOrdinary($expected->id);
        $this->requirePrincipal($principal, $current);
    }

    private function requireOrdinary(string $sessionId): void
    {
        if ($this->overlays->find($sessionId)) {
            throw new IdentityException('ordinary_action_required', 403);
        }
    }

    private function requirePrincipal(Principal $principal, IdentitySession $row): void
    {
        $decision = $principal->decision;
        if (($decision['contract'] ?? null) !== 'platform-authorization-snapshot.v1' || ! array_key_exists('delegation', $decision) || $decision['delegation'] !== null
            || ($decision['subject']) !== $row->subject || ($decision['central_session_id'] ?? null) !== $row->sid
            || ($decision['issuer'] ?? null) !== $this->config->issuer() || ($decision['application_id'] ?? null) !== $this->config->applicationId()
            || ($decision['client_id'] ?? null) !== $this->config->clientId() || ($decision['organization_id'] ?? null) !== ($row->selection['organizationId'] ?? null)
            || ($decision['selected_role_id'] ?? null) !== ($row->selection['roleId'] ?? null) || (Contract::date($decision['expires_at']) ?? 0) <= microtime(true)) {
            throw new IdentityException('ordinary_authority_expired', 409);
        }
    }
}
