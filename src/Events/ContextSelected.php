<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Events;

/** Safe immutable notification; never an authorization grant. */
final readonly class ContextSelected
{
    public function __construct(public string $consumer, public string $actorSubject, public ?string $organizationId, public ?string $roleId, public int $contextVersion) {}
}
