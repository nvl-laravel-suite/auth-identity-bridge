<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use IdentityPlatform\Laravel\Authorization\CurrentDecisionView;
use JsonSerializable;

/**
 * Safe current browser facts; every operation still requires fresh server authority.
 *
 * @phpstan-import-type DecisionFacts from CurrentDecisionView
 * @phpstan-import-type IdentityFacts from IdentityView
 * @phpstan-import-type ContextFacts from \IdentityPlatform\Laravel\ApplicationContext\ApplicationContextDescriptor
 *
 * @phpstan-type StateFacts array{consumer: string, actor: IdentityFacts|null, effectiveSubject: IdentityFacts|null, contextVersion: int|null, decision: DecisionFacts, delegation: array{status: string, expiresAt: string|null}, applicationContext: ContextFacts|null}
 */
final readonly class AuthStateView implements JsonSerializable
{
    /** @param ContextFacts|null $applicationContext */
    public function __construct(public string $consumer, public ?IdentityView $actor = null, public ?IdentityView $effectiveSubject = null, public ?int $contextVersion = null, public CurrentDecisionView $decision = new CurrentDecisionView, public string $delegationStatus = 'none', public ?string $delegationExpiresAt = null, public ?array $applicationContext = null) {}

    /** @return StateFacts */
    public function toArray(): array
    {
        return ['consumer' => $this->consumer, 'actor' => $this->actor?->jsonSerialize(), 'effectiveSubject' => $this->effectiveSubject?->jsonSerialize(), 'contextVersion' => $this->contextVersion,
            'decision' => $this->decision->toArray(), 'delegation' => ['status' => $this->delegationStatus, 'expiresAt' => $this->delegationExpiresAt], 'applicationContext' => $this->applicationContext];
    }

    /** @return StateFacts */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
