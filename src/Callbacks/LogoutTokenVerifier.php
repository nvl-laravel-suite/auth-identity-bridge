<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Callbacks;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Oidc\TrustedProviderMetadata;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use stdClass;
use Throwable;

/** Uses the configured OP's keys; token-selected URLs and embedded keys have no authority. */
final class LogoutTokenVerifier
{
    private const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function __construct(private IdentityConfig $config, private IdentityHttp $http) {}

    public function verify(string $token): array
    {
        try {
            $segments = explode('.', $token);
            if (count($segments) !== 3 || strlen($token) > 65536 ||
                ! preg_match('/\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/', $token)) {
                throw new \UnexpectedValueException;
            }
            $header = json_decode(JWT::urlsafeB64Decode($segments[0]), false, 32, JSON_THROW_ON_ERROR);
            if (! $header instanceof stdClass || ! in_array($header->alg ?? null, ['EdDSA', 'ES256', 'RS256'], true) ||
                ($header->typ ?? null) !== 'logout+jwt' || property_exists($header, 'crit') ||
                (property_exists($header, 'b64') && $header->b64 !== true) ||
                (property_exists($header, 'kid') && ! self::identifier($header->kid))) {
                throw new \UnexpectedValueException;
            }
        } catch (Throwable) {
            throw new IdentityException('logout_token_invalid', 400);
        }
        $key = $this->key($header);
        try {
            try {
                $claims = JWT::decode($token, $key);
            } catch (BeforeValidException|ExpiredException $exception) {
                // firebase verifies the signature before these time exceptions. Check all
                // times below to retain the OP's +30s iat allowance without nbf/exp leeway.
                $claims = $exception->getPayload();
            }
            $now = (float) now()->format('U.u');
            $audience = $claims->aud ?? null;
            $events = $claims->events ?? null;
            $entry = $events instanceof stdClass ? ($events->{self::EVENT} ?? null) : null;
            if (($claims->iss ?? null) !== $this->config->issuer() ||
                ! ($audience === $this->config->clientId() || (is_array($audience) && array_is_list($audience) && in_array($this->config->clientId(), $audience, true) && count(array_filter($audience, 'is_string')) === count($audience))) ||
                ! self::number($claims->iat ?? null) || $claims->iat > $now + 30 || $now - $claims->iat > 300 ||
                ! self::identifier($claims->jti ?? null) || property_exists($claims, 'nonce') ||
                (! self::identifier($claims->sid ?? null) && ! self::identifier($claims->sub ?? null)) ||
                (property_exists($claims, 'sid') && ! self::identifier($claims->sid)) ||
                (property_exists($claims, 'sub') && ! self::identifier($claims->sub)) ||
                ! $events instanceof stdClass || count((array) $events) !== 1 ||
                ! $entry instanceof stdClass || count((array) $entry) !== 0 ||
                (property_exists($claims, 'exp') && (! self::number($claims->exp) || $claims->exp <= $claims->iat || $claims->exp <= $now)) ||
                (property_exists($claims, 'nbf') && (! self::number($claims->nbf) || $claims->nbf > $now))) {
                throw new \UnexpectedValueException;
            }

            return array_filter([
                'jti' => $claims->jti, 'sid' => $claims->sid ?? null, 'sub' => $claims->sub ?? null,
            ], static fn ($value) => $value !== null);
        } catch (Throwable) {
            throw new IdentityException('logout_token_invalid', 400);
        }
    }

    private function key(stdClass $header): Key
    {
        try {
            $provider = new TrustedProviderMetadata($this->config, $this->http);
            $jwks = $provider->getJwks();
            if (isset($header->kid) && ! in_array($header->kid, array_column($jwks['keys'], 'kid'), true)) {
                $jwks = $provider->reload()->getJwks();
            }
            $keys = [];
            foreach ($jwks['keys'] as $jwk) {
                if (! is_array($jwk) || isset($jwk['d']) ||
                    (isset($header->kid) && ($jwk['kid'] ?? null) !== $header->kid) ||
                    (isset($jwk['alg']) && $jwk['alg'] !== $header->alg) ||
                    (isset($jwk['use']) && $jwk['use'] !== 'sig') ||
                    (isset($jwk['key_ops']) && (! is_array($jwk['key_ops']) || ! in_array('verify', $jwk['key_ops'], true)))) {
                    continue;
                }
                $compatible = match ($header->alg) {
                    'EdDSA' => ($jwk['kty'] ?? null) === 'OKP' && ($jwk['crv'] ?? null) === 'Ed25519',
                    'ES256' => ($jwk['kty'] ?? null) === 'EC' && ($jwk['crv'] ?? null) === 'P-256',
                    'RS256' => ($jwk['kty'] ?? null) === 'RSA',
                };
                if ($compatible) {
                    $keys[] = JWK::parseKey($jwk, $header->alg);
                }
            }
            if (count($keys) !== 1 || ! $keys[0] instanceof Key) {
                throw new IdentityException('logout_token_invalid', 400);
            }

            return $keys[0];
        } catch (IdentityException $exception) {
            if ($exception->errorCode === 'logout_token_invalid') {
                throw $exception;
            }
            throw new IdentityException('logout_keys_unavailable');
        } catch (Throwable) {
            throw new IdentityException('logout_keys_unavailable');
        }
    }

    private static function identifier(mixed $value): bool
    {
        return is_string($value) && $value !== '' && mb_check_encoding($value, 'UTF-8') &&
            strlen(mb_convert_encoding($value, 'UTF-16LE', 'UTF-8')) <= 510 && ! preg_match('/[\x00-\x1f\x7f]/', $value);
    }

    private static function number(mixed $value): bool
    {
        return (is_int($value) || is_float($value)) && is_finite((float) $value);
    }
}
