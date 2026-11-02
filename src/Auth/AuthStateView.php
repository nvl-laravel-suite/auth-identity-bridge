<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use IdentityPlatform\Laravel\Authorization\CurrentDecisionView;
use JsonSerializable;

final readonly class AuthStateView implements JsonSerializable
{
    public function __construct(public string $consumer, public ?IdentityView $actor = null, public ?IdentityView $effectiveSubject = null, public ?int $contextVersion = null, public CurrentDecisionView $decision = new CurrentDecisionView, public string $delegationStatus = 'none', public ?string $delegationExpiresAt = null, public ?array $applicationContext = null) {}

    public function toArray(): array
    {
        return ['consumer' => $this->consumer, 'actor' => $this->actor?->jsonSerialize(), 'effectiveSubject' => $this->effectiveSubject?->jsonSerialize(), 'contextVersion' => $this->contextVersion,
            'decision' => $this->decision->toArray(), 'delegation' => ['status' => $this->delegationStatus, 'expiresAt' => $this->delegationExpiresAt], 'applicationContext' => $this->applicationContext];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
