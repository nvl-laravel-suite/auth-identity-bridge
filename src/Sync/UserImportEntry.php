<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

final readonly class UserImportEntry
{
    /**
     * @param  array<array-key, mixed>  $user
     */
    public function __construct(#[\SensitiveParameter] private array $user, public int|string $nativeUserId) {}

    /** Credential-bearing data for synchronous import only. Never log or queue this return value.
     *
     * @return array<array-key, mixed>
     */
    public function payload(): array
    {
        return $this->user;
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
