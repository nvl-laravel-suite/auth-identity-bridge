<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

use JsonSerializable;

/** Finite presentation only. selectedRole is a selected app role KEY, never a role ID. */
final readonly class CurrentDecisionView implements JsonSerializable
{
    public function __construct(public array $permissions = [], public ?string $selectedRole = null, public ?string $organizationId = null, public ?string $expiresAt = null, public ?int $contextVersion = null) {}

    public function toArray(): array
    {
        return ['permissions' => $this->permissions, 'selectedRole' => $this->selectedRole, 'organizationId' => $this->organizationId, 'expiresAt' => $this->expiresAt, 'contextVersion' => $this->contextVersion];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
