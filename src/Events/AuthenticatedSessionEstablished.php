<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Events;

/** Safe immutable notification; never an authorization grant. */
final readonly class AuthenticatedSessionEstablished
{
    public function __construct(public string $consumer, public string $actorSubject, public int $contextVersion) {}
}
