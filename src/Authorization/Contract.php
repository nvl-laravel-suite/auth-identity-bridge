<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Authorization;

use DateTimeImmutable;
use IdentityPlatform\Laravel\Exceptions\IdentityException;

/** Small runtime checks for provider-owned JSON contracts, not JWT cryptography. */
final class Contract
{
    /** @phpstan-assert true $condition */
    public static function require(bool $condition, string $code = 'invalid_authorization_response', int $status = 401): void
    {
        if (! $condition) {
            throw new IdentityException($code, $status);
        }
    }

    /** @phpstan-assert-if-true =non-empty-string $value */
    public static function identifier(mixed $value): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= 128 && ! str_contains($value, "\0");
    }

    /** @phpstan-assert-if-true =non-empty-string|null $value */
    public static function nullableIdentifier(mixed $value): bool
    {
        return $value === null || self::identifier($value);
    }

    /** @phpstan-assert-if-true =positive-int $value */
    public static function positive(mixed $value): bool
    {
        return is_int($value) && $value > 0;
    }

    /** @phpstan-assert-if-true =list<non-empty-string> $value */
    public static function strings(mixed $value, bool $permissions = false): bool
    {
        if (! is_array($value) || ! array_is_list($value)) {
            return false;
        }
        foreach ($value as $item) {
            if (! self::identifier($item) || ($permissions && ! preg_match('/^[a-z][a-z0-9._:-]{1,127}$/D', $item))) {
                return false;
            }
        }

        return count($value) === count(array_unique($value));
    }

    public static function date(mixed $value): ?float
    {
        if (! is_string($value) || ! preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/D', $value)) {
            return null;
        }
        $parts = date_parse($value);
        if ($parts['warning_count'] !== 0 || $parts['error_count'] !== 0) {
            return null;
        }

        return (float) (new DateTimeImmutable($value))->format('U.u');
    }

    /** @param array<array-key, mixed> $data */
    public static function lifetime(array $data, int $maximum = 60, int $futureTolerance = 0): bool
    {
        $issued = self::date($data['issued_at'] ?? null);
        $expires = self::date($data['expires_at'] ?? null);
        $now = microtime(true);

        return $issued !== null && $expires !== null && $issued <= $now + $futureTolerance
            && $expires > $now && $expires > $issued && $expires - $issued <= $maximum && $now - $issued <= $maximum;
    }

    /**
     * @template TKey of array-key
     *
     * @param  array<array-key, mixed>  $data
     * @param  list<TKey>  $required
     * @param  list<TKey>  $optional
     *
     * @phpstan-assert-if-true =array<TKey, mixed> $data
     */
    public static function keys(array $data, array $required, array $optional = []): bool
    {
        return array_diff($required, array_keys($data)) === [] && array_diff(array_keys($data), [...$required, ...$optional]) === [];
    }
}
