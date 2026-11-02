<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

final readonly class UserImportPage
{
    /** @param array<array-key, mixed> $entries */
    public function __construct(#[\SensitiveParameter] private array $entries, public ?string $nextCursor) {}

    /** Synchronous use only.
     *
     * @return array<array-key, mixed>
     */
    public function entries(): array
    {
        return $this->entries;
    }

    public function __debugInfo(): array
    {
        return ['redacted' => true];
    }

    public function __serialize(): array
    {
        throw new \LogicException('Import credentials cannot be serialized.');
    }
}
