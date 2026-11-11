<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

/** Integer-backed host enum for native value transforms. */
enum IntegerTierFixture: int
{
    case Standard = 1;
    case Premium = 2;
}
