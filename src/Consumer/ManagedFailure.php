<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Consumer;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use JsonSerializable;
use Throwable;

/** No provider body, exception text, input or credential crosses this boundary. */
final readonly class ManagedFailure implements JsonSerializable
{
    private const CODES = [
        'validation_failed' => 'validation', 'consumer_profile_field_denied' => 'refusal',
        'consumer_global_effect_acknowledgement_required' => 'refusal', 'consumer_resource_unavailable' => 'refusal',
        'consumer_capability_denied' => 'refusal', 'app_administration_denied' => 'refusal',
        'consumer_disabled' => 'refusal', 'access_inactive' => 'refusal', 'delegation_control_plane_forbidden' => 'refusal',
        'version_conflict' => 'conflict', 'idempotency_conflict' => 'conflict', 'operation_pending' => 'recovery_pending',
        'mfa_required' => 'mfa', 'sign_in_required' => 'authentication', 'session_inactive' => 'authentication', 'token_inactive' => 'authentication',
        'context_required' => 'context_changed', 'context_changed' => 'context_changed',
        'recovery_unavailable' => 'recovery_pending', 'invalid_command_reference' => 'recovery_pending',
    ];

    private function __construct(public string $kind, public string $code) {}

    public static function from(Throwable $error): self
    {
        $code = $error instanceof IdentityException ? $error->errorCode : '';

        return isset(self::CODES[$code]) ? new self(self::CODES[$code], $code) : new self('provider_unavailable', 'provider_unavailable');
    }

    public static function refused(Throwable $error): bool
    {
        return $error instanceof IdentityException && $error->status >= 400 && $error->status < 500
            && isset(self::CODES[$error->errorCode]) && self::CODES[$error->errorCode] !== 'recovery_pending';
    }

    /** @return array{kind: string, code: string} */
    public function jsonSerialize(): array
    {
        return ['kind' => $this->kind, 'code' => $this->code];
    }

    public function httpStatus(): int
    {
        return match ($this->kind) {
            'validation' => 400, 'authentication' => 401, 'refusal', 'mfa' => 403,
            'conflict', 'context_changed' => 409, default => 503,
        };
    }
}
