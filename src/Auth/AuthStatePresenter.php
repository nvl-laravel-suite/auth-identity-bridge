<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextManager;
use IdentityPlatform\Laravel\Authorization\CurrentDecisionView;
use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Delegation\DelegationDecision;
use IdentityPlatform\Laravel\Delegation\IdentityDelegation;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserProjectionRepository;
use Illuminate\Http\Request;

/** Stable, allowlisted presentation only; every operation still requires current authority. */
final class AuthStatePresenter
{
    public function __construct(private Request $request, private IdentityConfig $config, private SessionManager $sessions, private SessionRepository $rows, private OverlayRepository $overlays, private UserProjectionRepository $projections, private IdentityAccess $access, private ApplicationContextManager $applicationContexts) {}

    public function current(): AuthStateView
    {
        $empty = new AuthStateView($this->config->context()->name());
        try {
            $source = $this->sessions->current($this->request);
            if (! $source) {
                return $empty;
            }
            $overlay = $this->overlays->find($source->id);
            $mode = $this->mode($overlay);
            $profile = $this->projections->find($source->user_id);
            $actor = new IdentityView($source->subject, $profile?->name, $profile?->email, $profile?->picture);
            $effective = $actor;
            $decision = new CurrentDecisionView;
            $status = $overlay?->status ?? 'none';
            if ($overlay) {
                $effective = null;
                if ($overlay->status === 'active') {
                    $proof = $this->request->attributes->get('identity.delegation');
                    if (! $proof instanceof DelegationDecision) {
                        throw new IdentityException('delegation_check_required', 403);
                    }
                    $validated = DelegationDecision::validate($proof->data, $source, $overlay, $this->config);
                    $subject = $validated->data['subject'];
                    $effective = new IdentityView($subject['id'], $subject['name'], $subject['email']);
                    $decision = $this->access->currentDecisionView();
                }
            } elseif (($source->selection['selected'] ?? false) === true) {
                $decision = $this->access->currentDecisionView();
            }
            $applicationContext = $overlay ? null : $this->applicationContexts->forSource($source);
            $current = $this->rows->find($source->id);
            $stamp = ['id', 'binding_hash', 'subject', 'sid', 'user_id', 'selection', 'context_version', 'token_generation', 'application_context'];
            if ($this->request->session()->get('identity.session') !== $source->id || ! $current || ! $this->sessions->live($current) || $source->only($stamp) !== $current->only($stamp)
                || $mode !== $this->mode($this->overlays->find($source->id))
                || ($decision->contextVersion !== null && $decision->contextVersion !== $source->context_version)
                || ($decision->expiresAt !== null && strtotime($decision->expiresAt) <= microtime(true))
                || ($applicationContext && ! $applicationContext->expiresAt->isFuture())
                || ($overlay && $overlay->expires_at->isPast())) {
                return $empty;
            }

            return new AuthStateView($empty->consumer, $actor, $effective, $source->context_version, $decision, $status, $overlay?->expires_at->toIso8601String(), $applicationContext?->jsonSerialize());
        } catch (IdentityException) {
            return $empty;
        }
    }

    private function mode(?IdentityDelegation $overlay): ?array
    {
        // Internal comparison only. Never serialize an overlay, its handle or decision ledger.
        return $overlay ? array_intersect_key($overlay->getRawOriginal(), array_flip(['id', 'binding_hash', 'source_sid', 'status', 'browser_binding', 'context_version', 'decision', 'handle_vault', 'expires_at'])) : null;
    }
}
