<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

final readonly class UserImportMapping
{
    public function __construct(public string $sourceUserId, public UserSnapshot $snapshot) {}
}
