<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Callbacks;

use DateTimeImmutable;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use JsonException;
use stdClass;

/** Authenticates the delivered bytes before interpreting the strict public envelope. */
final class IdentityEventVerifier
{
    private const TYPES = [
        'application.created', 'application.configured', 'application.status_changed',
        'catalog.published', 'entitlements.changed', 'grant.updated', 'grant.revoked',
        'profile.invalidated',
        'client.created', 'client.configured', 'client.secret_rotated', 'client.revoked', 'client.grants_revoked',
        'invitation.created', 'invitation.accepted', 'invitation.revoked',
        'credential.created', 'credential.rotated', 'credential.revoked',
        'resource_client.created', 'resource_client.rotated', 'resource_client.revoked',
        'service.created', 'service.updated', 'service.client_revoked', 'service.key_revoked',
    ];

    public function __construct(private IdentityConfig $config) {}

    public function verify(string $rawBody, array $headers): array
    {
        $secret = $this->config->value('callbacks.event_secret');
        if ($secret === null || $secret === '') {
            throw new IdentityException('event_receiver_disabled', 404);
        }
        $previous = $this->config->value('callbacks.event_secret_previous');
        $expires = $this->config->value('callbacks.event_secret_previous_expires_at');
        if (is_string($previous) && trim($previous) === '') {
            $previous = null;
        }
        if (is_string($expires) && trim($expires) === '') {
            $expires = null;
        }
        if (($previous !== null || $expires !== null) &&
            (! is_string($previous) || strlen($previous) < 32 || strlen($previous) > 1024 || ! self::instant($expires))) {
            throw new IdentityException('event_receiver_configuration_invalid', 503);
        }
        $now = now()->getTimestamp();
        $eventId = $this->header($headers, 'x-identity-event-id');
        $timestamp = $this->header($headers, 'x-identity-timestamp');
        $signature = $this->header($headers, 'x-identity-signature');
        if (! is_string($secret) || strlen($secret) < 32 ||
            ! preg_match('/\A[A-Za-z0-9_-]{1,128}\z/', $eventId) ||
            ! preg_match('/\A[0-9]{1,12}\z/', $timestamp) ||
            ! preg_match('/\Av1=[a-f0-9]{64}\z/', $signature) ||
            abs($now - (int) $timestamp) > 300) {
            throw new IdentityException('event_signature_invalid', 401);
        }
        $keys = [$secret];
        if ($previous !== null && $now < (new DateTimeImmutable($expires))->getTimestamp()) {
            $keys[] = $previous;
        }
        $matched = false;
        foreach ($keys as $key) {
            $valid = hash_equals('v1='.hash_hmac('sha256', $eventId.'.'.$timestamp.'.'.$rawBody, $key), $signature);
            $matched = $valid || $matched;
        }
        if (! $matched) {
            throw new IdentityException('event_signature_invalid', 401);
        }
        try {
            $payload = json_decode($rawBody, false, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new IdentityException('event_payload_invalid', 400);
        }
        if (! $payload instanceof stdClass) {
            throw new IdentityException('event_payload_invalid', 400);
        }
        $event = (array) $payload;
        $keys = array_keys($event);
        sort($keys);
        if ($keys !== ['application_id', 'event_id', 'occurred_at', 'schema_version', 'subject', 'type'] ||
            $event['schema_version'] !== 1 || ! self::identifier($event['event_id']) ||
            ! self::identifier($event['application_id']) ||
            ! in_array($event['type'], self::TYPES, true) ||
            ! self::instant($event['occurred_at']) ||
            ($event['subject'] !== null && ! self::identifier($event['subject']))) {
            throw new IdentityException('event_payload_invalid', 400);
        }
        if ($event['event_id'] !== $eventId) {
            throw new IdentityException('event_id_mismatch', 400);
        }
        if ($event['application_id'] !== $this->config->applicationId()) {
            throw new IdentityException('event_application_mismatch', 400);
        }
        if ((str_starts_with($event['type'], 'grant.') || $event['type'] === 'profile.invalidated') && $event['subject'] === null) {
            throw new IdentityException('event_subject_required', 400);
        }

        return $event;
    }

    private function header(array $headers, string $name): string
    {
        $found = [];
        foreach ($headers as $key => $value) {
            if (strtolower((string) $key) === $name) {
                array_push($found, ...is_array($value) ? array_values($value) : [$value]);
            }
        }

        return count($found) === 1 && is_string($found[0]) ? $found[0] : '';
    }

    private static function identifier(mixed $value): bool
    {
        return is_string($value) && $value !== '' && ! str_contains($value, "\0") &&
            strlen(mb_convert_encoding($value, 'UTF-16LE', 'UTF-8')) <= 256;
    }

    private static function instant(mixed $value): bool
    {
        if (! is_string($value) || ! preg_match('/\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.[0-9]+)?)?Z\z/', $value, $parts)) {
            return false;
        }

        return checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1]) &&
            (int) $parts[4] < 24 && (int) $parts[5] < 60 && (int) ($parts[6] ?? 0) < 60;
    }
}
