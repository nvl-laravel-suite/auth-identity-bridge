<?php

namespace IdentityPlatform\Laravel\Tests\Sync;

final class ProfileFixture
{
    public static function consumer(array $changes = []): array
    {
        return array_diff_key(self::profile($changes), array_flip(['emailVerified', 'picture', 'adminNotes', 'tags', 'lastLoginAt']));
    }

    public static function profile(array $changes = []): array
    {
        return array_replace([
            'name' => 'Current name', 'email' => 'current@example.test', 'emailVerified' => true,
            'picture' => null, 'locale' => 'bg', 'timezone' => 'Europe/Sofia', 'accountType' => 'individual',
            'phone' => null, 'organizationName' => null, 'position' => null, 'bio' => null,
            'dateOfBirth' => null, 'gender' => null, 'country' => null, 'socialLinks' => null,
            'profileCompleted' => false, 'adminNotes' => null, 'tags' => [], 'lastLoginAt' => null,
        ], $changes);
    }
}
