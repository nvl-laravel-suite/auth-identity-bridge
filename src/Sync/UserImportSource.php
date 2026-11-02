<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

/** Trusted host adapter: read-only, stable nonsecret IDs/cursors, no logging or export retention. */
interface UserImportSource
{
    public function page(?string $cursor, int $limit): UserImportPage;
}
