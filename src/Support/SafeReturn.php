<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

final class SafeReturn
{
    public static function path(mixed $value): string
    {
        if (! is_string($value) || strlen($value) > 2048) {
            return '/';
        }
        $decoded = $value;
        for ($i = 0; $i < 4; $i++) {
            if (! str_starts_with($decoded, '/') || str_starts_with($decoded, '//') || preg_match('/[\x00-\x20\x7f\\\\]/', $decoded) || preg_match('~(?:^|/)\.{1,2}(?:/|$|[?#])~', $decoded)) {
                return '/';
            }
            $next = rawurldecode($decoded);
            if ($next === $decoded) {
                return $value;
            }
            $decoded = $next;
        }

        return '/';
    }
}
