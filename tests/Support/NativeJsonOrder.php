<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Support;

/** Reproduces MySQL's native JSON normalization: object keys are stored by length, then bytes. */
final class NativeJsonOrder
{
    public static function normalize(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }
        if (! array_is_list($value)) {
            uksort($value, static fn (int|string $left, int|string $right): int => [strlen((string) $left), (string) $left] <=> [strlen((string) $right), (string) $right]);
        }

        return array_map(self::normalize(...), $value);
    }

    public static function encode(mixed $value): string
    {
        return json_encode(self::normalize($value), JSON_THROW_ON_ERROR);
    }
}
