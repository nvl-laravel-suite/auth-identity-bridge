<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

/** The public provider contract's bounded import formats; never verifies or stores a credential. */
final class ImportedPasswordHash
{
    public static function supported(#[\SensitiveParameter] string $hash): bool
    {
        if (strlen($hash) > 512) {
            return false;
        }
        if (preg_match('/^\$2[aby]\$(\d{2})\$[.\/A-Za-z0-9]{53}$/D', $hash, $parts)) {
            return (int) $parts[1] >= 4 && (int) $parts[1] <= 14;
        }
        if (! preg_match('/^\$argon2id\$v=19\$m=([1-9]\d{0,5}),t=([1-9]\d?),p=([1-9]\d?)\$([A-Za-z0-9+\/]+)\$([A-Za-z0-9+\/]+)$/D', $hash, $parts)) {
            return false;
        }
        [, $memory, $time, $parallelism, $salt, $digest] = $parts;
        $valid = static function (string $value, int $min): bool {
            $bytes = base64_decode($value, true);

            return $bytes !== false && rtrim(base64_encode($bytes), '=') === $value && strlen($bytes) >= $min && strlen($bytes) <= 64;
        };

        return (int) $memory >= 8 * (int) $parallelism && (int) $memory <= 65536 && (int) $time <= 6 && (int) $parallelism <= 4 && $valid($salt, 8) && $valid($digest, 16);
    }
}
