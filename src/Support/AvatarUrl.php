<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

final class AvatarUrl
{
    public static function safe(mixed $url): ?string
    {
        if (! is_string($url) || strlen($url) > 8192 || filter_var($url, FILTER_VALIDATE_URL) === false || preg_match('/[\x00-\x20\x7f]/', $url)) {
            return null;
        }
        $parts = parse_url($url);

        return $parts && ($parts['scheme'] ?? null) === 'https' && ! isset($parts['user']) && ! isset($parts['pass']) ? $url : null;
    }
}
