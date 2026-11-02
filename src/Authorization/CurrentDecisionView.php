<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

use JsonSerializable;

/**
 * Finite presentation only. selectedRole is a selected app role KEY, never a role ID.
 *
 * @phpstan-type DecisionFacts array{permissions: list<string>, selectedRole: string|null, organizationId: string|null, expiresAt: string|null, contextVersion: int|null}
 */
final readonly class CurrentDecisionView implements JsonSerializable
{
    /** @param list<string> $permissions */
    public function __construct(public array $permissions = [], public ?string $selectedRole = null, public ?string $organizationId = null, public ?string $expiresAt = null, public ?int $contextVersion = null) {}

    /** @return DecisionFacts */
    public function toArray(): array
    {
        return ['permissions' => $this->permissions, 'selectedRole' => $this->selectedRole, 'organizationId' => $this->organizationId, 'expiresAt' => $this->expiresAt, 'contextVersion' => $this->contextVersion];
    }

    /** @return DecisionFacts */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
