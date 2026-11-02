<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Delegation\DelegationDecision;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserProjectionRepository;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use IdentityPlatform\Laravel\Users\NativeOwner;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

/** Browser authority belongs to the bound request and is never an ambient job principal.
 * @api
 */
class IdentityAccess
{
    public function __construct(private ConsumerGraph $graph, protected Request $request, protected SessionManager $sessions, protected UserProjectionRepository $projections, protected IdentityUserResolver $resolver, protected OverlayRepository $overlays) {}

    public function setRequest(Request $request): void
    {
        $this->request = $request;
    }

    public function projection(): ?IdentityUser
    {
        $decision = $this->effectiveDecision();
        if ($decision) {
            $subject = $decision->data['subject'];

            return $this->graph->make(UserSynchronizer::class)->sync(['sub' => $subject['id'], 'name' => $subject['name'], 'email' => $subject['email']]);
        }

        return $this->actorProjection();
    }

    private function actorProjection(): ?IdentityUser
    {
        $row = $this->sessions->current($this->request);

        return $row ? $this->projections->find($row->user_id) : null;
    }

    public function user(): ?Authenticatable
    {
        $projection = $this->projection();

        return $projection ? $this->resolver->resolve($projection) : null;
    }

    public function actor(): ?Authenticatable
    {
        $projection = $this->actorProjection();

        return $projection ? $this->resolver->resolve($projection) : null;
    }

    public function isImpersonating(): bool
    {
        $row = $this->sessions->current($this->request);

        return $row !== null && $this->overlays->find($row->id) !== null;
    }

    public function principal(bool $fresh = false): Principal
    {
        $decision = $this->effectiveDecision();
        if ($decision) {
            if (! in_array($this->request->method(), ['GET', 'HEAD'], true)) {
                return $this->assertFreshContext();
            }

            return $decision->principal();
        }
        if (! in_array($this->request->method(), ['GET', 'HEAD'], true)) {
            return $this->assertFreshContext();
        }

        return $this->sessions->principal($this->request, $fresh);
    }

    public function hasPermission(string $permission, bool $fresh = false): bool
    {
        return $this->principal($fresh)->hasPermission($permission);
    }

    /** The single selected application role key; assigned role unions never authorize. */
    public function hasSelectedRole(string $role, bool $fresh = false): bool
    {
        return $this->principal($fresh)->selectedRole() === $role;
    }

    public function organizationId(): ?string
    {
        return $this->principal()->organizationId();
    }

    public function contextVersion(): ?int
    {
        return $this->sessions->current($this->request)?->context_version;
    }

    /** Capture display authority and its local context together; never mix two selections. */
    public function currentDecisionView(): CurrentDecisionView
    {
        $source = $this->sessions->current($this->request) ?? throw new IdentityException('sign_in_required', 401);
        $principal = $this->principal(true);
        $view = new CurrentDecisionView($principal->permissions(), $principal->selectedRole(), $principal->organizationId(), $principal->decision['expires_at'], $source->context_version);
        $current = $this->sessions->current($this->request);
        $stamp = ['id', 'binding_hash', 'subject', 'sid', 'user_id', 'selection', 'context_version', 'token_generation'];
        if (! $current || ! Contract::positive($source->context_version) || $source->only($stamp) !== $current->only($stamp)) {
            throw new IdentityException('context_changed', 409);
        }

        return $view;
    }

    public function assertOwner(Authenticatable $owner): void
    {
        $user = $this->user();
        if (! $user || NativeOwner::key($user) !== NativeOwner::key($owner)) {
            throw new IdentityException('access_denied', 403);
        }
    }

    public function assertFreshContext(): Principal
    {
        $row = $this->sessions->current($this->request) ?? throw new IdentityException('sign_in_required', 401);
        $version = $this->request->input('context_version', $this->request->header('X-Identity-Context-Version'));
        if (! is_scalar($version) || ! ctype_digit((string) $version) || (int) $version !== $row->context_version) {
            throw new IdentityException('context_changed', 409);
        }
        $decision = $this->effectiveDecision();
        $principal = $decision ? $decision->principal() : $this->sessions->principal($this->request, true);
        $this->request->attributes->set('identity.principal', $principal);
        $this->request->attributes->set('identity.principal.fresh', true);

        return $principal;
    }

    private function effectiveDecision(): ?DelegationDecision
    {
        $row = $this->sessions->current($this->request);
        $overlay = $row ? $this->overlays->find($row->id) : null;
        if (! $overlay) {
            return null;
        }
        $decision = $this->request->attributes->get('identity.delegation');
        if ($overlay->status !== 'active' || $overlay->expires_at->isPast() || ! $decision instanceof DelegationDecision) {
            throw new IdentityException('delegation_check_required', 403);
        }

        return DelegationDecision::validate($decision->data, $row, $overlay, $this->graph->make(IdentityConfig::class));
    }
}
