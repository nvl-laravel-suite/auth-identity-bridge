<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\ApplicationContext;

use Carbon\CarbonImmutable;
use JsonSerializable;

/** Safe binding facts only; source row/SID/native identity stay in private persistence. */
final readonly class ApplicationContextDescriptor implements JsonSerializable
{
    public function __construct(public string $kind, public string $resourceId, public string $label, public string $consumerBinding, public string $actorSubject, public array $providerSelection, public string $version, public CarbonImmutable $expiresAt) {}

    public function jsonSerialize(): array
    {
        return ['kind' => $this->kind, 'resourceId' => $this->resourceId, 'label' => $this->label, 'consumerBinding' => $this->consumerBinding, 'actorSubject' => $this->actorSubject,
            'providerSelection' => $this->providerSelection, 'version' => $this->version, 'expiresAt' => $this->expiresAt->utc()->toISOString()];
    }
}
