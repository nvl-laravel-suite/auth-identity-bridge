<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

/**
 * Immutable authority returned by a validating authorization/resource/delegation boundary.
 *
 * @phpstan-type Decision array{subject: string, expires_at: string, permissions?: list<string>, roles?: list<string>, contract?: string, organization_id?: string|null, selected_role_id?: string|null, role_ids?: list<string>, assurance?: array{central_session_id: string, method: string, verified_at: string}|null, central_session_id?: string|null, ...<string, mixed>}
 */
final readonly class Principal
{
    /** @param Decision $decision */
    public function __construct(public array $decision) {}

    public function subject(): string
    {
        return $this->decision['subject'];
    }

    /** @return list<string> */
    public function permissions(): array
    {
        return $this->current() ? ($this->decision['permissions'] ?? []) : [];
    }

    /** @return list<string> */
    public function roles(): array
    {
        return $this->current() ? ($this->decision['roles'] ?? []) : [];
    }

    /** @phpstan-impure */
    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->permissions(), true);
    }

    /** @phpstan-impure */
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles(), true);
    }

    public function selectedRole(): ?string
    {
        $roles = $this->roles();

        return ($this->decision['contract'] ?? null) === 'platform-authorization-snapshot.v1'
            && Contract::identifier($this->decision['selected_role_id'] ?? null)
            && ($this->decision['role_ids'] ?? null) === [$this->decision['selected_role_id']]
            && Contract::strings($roles) && count($roles) === 1 ? $roles[0] : null;
    }

    public function organizationId(): ?string
    {
        return $this->decision['organization_id'] ?? null;
    }

    /** @phpstan-impure */
    public function recentMfa(int $maxAgeSeconds = 300): bool
    {
        $assurance = $this->decision['assurance'] ?? null;
        $verified = is_array($assurance) ? Contract::date($assurance['verified_at']) : null;

        return $this->current() && $maxAgeSeconds > 0 && ($this->decision['contract'] ?? null) === 'platform-authorization-snapshot.v1'
            && ($assurance['central_session_id'] ?? null) === ($this->decision['central_session_id'] ?? null)
            && ($assurance['method'] ?? null) === 'totp_or_recovery' && $verified !== null
            && $verified <= microtime(true) && microtime(true) - $verified <= min($maxAgeSeconds, 300);
    }

    /** @phpstan-impure */
    private function current(): bool
    {
        $expires = Contract::date($this->decision['expires_at']);

        return $expires !== null && $expires > microtime(true);
    }
}
