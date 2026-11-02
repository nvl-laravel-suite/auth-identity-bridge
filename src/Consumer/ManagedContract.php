<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Consumer;

use GuzzleHttp\Psr7\UriResolver;
use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\SharedProfile;
use League\Uri\Uri;
use Throwable;

/** PHP counterpart of the managed schemas in packages/contracts/src/{consumer,profile}.ts. */
final class ManagedContract
{
    public const WRITES = ['users.profile.update', 'users.metadata.update'];

    public const READS = ['users.profile.read', 'users.metadata.read'];

    public const PROFILE = ['name', 'locale', 'timezone', 'phone', 'organizationName', 'position', 'bio', 'dateOfBirth', 'gender', 'country', 'socialLinks', 'accountType'];

    public const METADATA = ['adminNotes', 'tags'];

    /** Check JSON kinds before PHP associative arrays erase object/list distinctions. */
    public static function jsonData(string $operation, \stdClass $data): array
    {
        if (in_array($operation, self::READS, true)) {
            self::response(($data->fields ?? null) instanceof \stdClass);
            self::response(is_array($data->writableFields ?? null));
            if (property_exists($data->fields, 'socialLinks') && $data->fields->socialLinks !== null) {
                self::response($data->fields->socialLinks instanceof \stdClass);
            }
            if (property_exists($data->fields, 'tags')) {
                self::response(is_array($data->fields->tags));
            }
        } elseif (in_array($operation, self::WRITES, true)) {
            self::response(is_array($data->changedFields ?? null));
        } elseif ($operation === 'operations.status' && in_array($data->operation ?? null, self::WRITES, true) && ($data->status ?? null) === 'completed') {
            self::response(($data->data ?? null) instanceof \stdClass);
            self::response(is_array($data->data->changedFields ?? null));
        }
        $convert = function ($value) use (&$convert) {
            return is_array($value) || $value instanceof \stdClass ? array_map($convert, (array) $value) : $value;
        };

        return $convert($data);
    }

    public static function input(string $operation, array $input): array
    {
        $write = in_array($operation, self::WRITES, true);
        self::require(in_array($operation, [...self::READS, ...self::WRITES, 'operations.status'], true));
        self::require(Contract::keys($input, $operation === 'operations.status' ? ['idempotencyKey'] : ($write ? ['userId', 'expectedVersion', 'changes', 'reason', 'idempotencyKey'] : ['userId'])));
        if ($operation === 'operations.status') {
            self::require(self::key($input['idempotencyKey']));

            return $input;
        }
        self::require(self::identifier($input['userId']));
        if ($write) {
            self::require(self::version($input['expectedVersion']) && $input['expectedVersion'] < 9007199254740991 && self::key($input['idempotencyKey']));
            self::require(is_string($input['reason']));
            $input['reason'] = self::trim($input['reason']);
            self::require(self::text($input['reason'], 500, 8));
            self::require(is_array($input['changes']) && $input['changes'] !== []);
            $input['changes'] = self::fields($operation, $input['changes'], true);
        }

        return $input;
    }

    public static function read(string $operation, array $data, array $input): array
    {
        try {
            self::require(Contract::keys($data, ['id', 'version', 'fields', 'writableFields']) && self::identifier($data['id']) && $data['id'] === ($input['userId'] ?? null) && self::version($data['version']) && is_array($data['fields']));
            $data['fields'] = self::fields($operation, $data['fields'], false);
            self::require($data['writableFields'] === [] || self::fieldNames($operation, $data['writableFields']));
            self::require(array_diff($data['writableFields'], array_keys($data['fields'])) === []);

            return $data;
        } catch (Throwable) {
            throw new IdentityException('invalid_consumer_response', 502);
        }
    }

    public static function receipt(string $operation, array $data, ?array $input = null): array
    {
        self::response(Contract::keys($data, ['id', 'version', 'operation', 'idempotencyKey', 'changedFields']) && in_array($operation, self::WRITES, true)
            && $data['operation'] === $operation && self::identifier($data['id']) && self::version($data['version']) && self::key($data['idempotencyKey']));
        $fields = $data['changedFields'];
        self::response(self::fieldNames($operation, $fields));
        if ($input !== null) {
            $expected = $input['changedFields'] ?? array_keys($input['changes'] ?? []);
            sort($expected, SORT_STRING);
            self::response($data['id'] === ($input['userId'] ?? null) && $data['idempotencyKey'] === ($input['idempotencyKey'] ?? null)
                && $data['version'] === ($input['expectedVersion'] ?? -1) + 1 && $fields === $expected);
        }

        return $data;
    }

    public static function status(array $data, array $reference): ?array
    {
        self::response(Contract::keys($data, ['operation', 'status', 'data']) && $data['operation'] === $reference['operation'] && in_array($data['status'], ['pending', 'completed'], true));
        if ($data['status'] === 'pending') {
            self::response($data['data'] === null);

            return null;
        }
        self::response(is_array($data['data']));

        return self::receipt($reference['operation'], $data['data'], $reference);
    }

    public static function fieldNames(string $operation, mixed $fields): bool
    {
        if (! is_array($fields) || ! array_is_list($fields) || $fields === []) {
            return false;
        }
        $allowed = str_starts_with($operation, 'users.metadata.') ? self::METADATA : self::PROFILE;
        foreach ($fields as $index => $field) {
            if (! is_string($field) || ! in_array($field, $allowed, true) || ($index > 0 && strcmp($fields[$index - 1], $field) >= 0)) {
                return false;
            }
        }

        return true;
    }

    public static function identifier(mixed $value): bool
    {
        return self::text($value, 128, 1);
    }

    public static function key(mixed $value): bool
    {
        return is_string($value) && preg_match('/^[A-Za-z0-9_.:-]{1,128}$/D', $value) === 1;
    }

    public static function version(mixed $value): bool
    {
        return is_int($value) && $value > 0 && $value <= 9007199254740991;
    }

    private static function fields(string $operation, array $fields, bool $write): array
    {
        $metadata = str_starts_with($operation, 'users.metadata.');
        $allowed = $metadata ? self::METADATA : [...self::PROFILE, ...($write ? [] : ['profileCompleted'])];
        self::require(array_diff(array_keys($fields), $allowed) === []);
        foreach ($fields as $key => &$value) {
            if (in_array($key, ['name', 'phone', 'organizationName', 'position', 'bio', 'adminNotes'], true)) {
                $limit = ['name' => 120, 'phone' => 32, 'organizationName' => 160, 'position' => 120, 'bio' => 2000, 'adminNotes' => 5000][$key];
                if ($value === null && $key !== 'name') {
                    continue;
                }
                self::require(is_string($value));
                $value = self::trim($value);
                self::require(self::text($value, $limit, $key === 'name' ? 1 : 0));
            } elseif ($key === 'locale') {
                self::require(in_array($value, ['en', 'bg'], true));
            } elseif ($key === 'timezone') {
                // Frozen from the shared Node schema's Intl.supportedValuesOf, not PHP aliases.
                $zones = json_decode(file_get_contents(__DIR__.'/profile-timezones.json'), true, flags: JSON_THROW_ON_ERROR);
                self::require(is_string($value) && in_array($value, $zones, true));
            } elseif ($key === 'tags') {
                self::require(is_array($value) && array_is_list($value) && count($value) <= 50);
                foreach ($value as &$tag) {
                    self::require(is_string($tag));
                    $tag = self::trim($tag);
                    self::require(self::text($tag, 64, 1));
                }
                unset($tag);
                self::require(count(array_unique($value, SORT_STRING)) === count($value));
                usort($value, fn ($a, $b) => strcmp(mb_convert_encoding($a, 'UTF-16BE', 'UTF-8'), mb_convert_encoding($b, 'UTF-16BE', 'UTF-8')));
            } elseif ($key === 'socialLinks') {
                if ($value === null) {
                    continue;
                }
                self::require(is_array($value) && count($value) <= 20);
                foreach ($value as $label => &$url) {
                    self::require(self::text((string) $label, 64, 1));
                    $url = self::url($url);
                }
                unset($url);
                ksort($value, SORT_STRING);
            } elseif ($key === 'dateOfBirth') {
                if ($value === null) {
                    continue;
                }
                self::require(is_string($value) && preg_match('/^\d{4}-\d{2}-\d{2}$/D', $value) === 1);
                $date = \DateTimeImmutable::createFromFormat('!Y-m-d', $value, new \DateTimeZone('UTC'));
                self::require($date !== false && $date->format('Y-m-d') === $value && $value <= gmdate('Y-m-d'));
            } else {
                // Reuse the existing shared enum/country validators, returning only supplied keys.
                $profile = array_fill_keys(SharedProfile::FIELDS, null);
                $profile = array_replace($profile, ['timezone' => 'UTC', 'accountType' => 'individual', 'profileCompleted' => false], [$key => $value]);
                self::require(SharedProfile::valid($profile));
            }
        }
        unset($value);

        return $fields;
    }

    private static function url(mixed $value): string
    {
        self::require(self::text($value, 2048, 1));
        try {
            // Maintained RFC parser. Deliberately refuse WHATWG-only backslash/control URL spellings.
            self::require(! preg_match('/[\x00-\x20\x7f\\\\]/', $value));
            $url = Uri::new($value);
            self::require($url->getScheme() === 'https' && $url->getHost() !== null && $url->getHost() !== '' && $url->getUserInfo() === null);
            $path = UriResolver::removeDotSegments($url->getPath());
            $normalized = $url->withPath($path === '' ? '/' : $path)->toString();
            self::require(self::text($normalized, 2048, 1));

            return $normalized;
        } catch (Throwable) {
            throw new IdentityException('validation_failed', 400);
        }
    }

    private static function trim(string $value): string
    {
        self::require(mb_check_encoding($value, 'UTF-8'));

        return preg_replace('/^[\x{0009}-\x{000D}\x{0020}\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]+|[\x{0009}-\x{000D}\x{0020}\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]+$/u', '', $value);
    }

    private static function text(mixed $value, int $maximum, int $minimum = 0): bool
    {
        if (! is_string($value) || ! mb_check_encoding($value, 'UTF-8') || str_contains($value, "\0")) {
            return false;
        }
        $length = strlen(mb_convert_encoding($value, 'UTF-16LE', 'UTF-8')) / 2;

        return $length >= $minimum && $length <= $maximum;
    }

    private static function require(bool $condition): void
    {
        Contract::require($condition, 'validation_failed', 400);
    }

    private static function response(bool $condition): void
    {
        Contract::require($condition, 'invalid_consumer_response', 502);
    }
}
