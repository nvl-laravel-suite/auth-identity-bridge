<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Oidc;

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

/** A synthetic provider transport with real Ed25519 signatures, never a live issuer. */
final class ProviderFixture
{
    public const ORIGIN = 'https://identity.example.test';

    public const ISSUER = self::ORIGIN.'/api/auth';

    public array $metadata;

    public array $claims;

    public array $userinfo = ['sub' => 'person-demo', 'name' => 'Synthetic Person', 'email' => 'person@example.test', 'email_verified' => true];

    public array $tokenOverrides = [];

    public bool $omitRefreshIdToken = false;

    public bool $omitIdToken = false;

    public ?string $rawIdToken = null;

    public array $requests = [];

    public int $tokenStatus = 200;

    public int $userinfoStatus = 200;

    public int $tokenDelayMicroseconds = 0;

    private string $secretKey;

    private string $publicKey;

    public function __construct()
    {
        $pair = sodium_crypto_sign_keypair();
        $this->secretKey = sodium_crypto_sign_secretkey($pair);
        $this->publicKey = sodium_crypto_sign_publickey($pair);
        $this->metadata = [
            'issuer' => self::ISSUER,
            'authorization_endpoint' => self::ISSUER.'/oauth2/authorize',
            'token_endpoint' => self::ISSUER.'/oauth2/token',
            'userinfo_endpoint' => self::ISSUER.'/oauth2/userinfo',
            'jwks_uri' => self::ISSUER.'/jwks',
            'end_session_endpoint' => self::ISSUER.'/oauth2/end-session',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'id_token_signing_alg_values_supported' => ['EdDSA', 'RS256', 'ES256'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        ];
        $this->claims = [
            'iss' => self::ISSUER,
            'aud' => 'web-demo',
            'sub' => 'person-demo',
            'sid' => 'central-session-demo',
            'nonce' => 'synthetic-nonce',
            // Native Better Auth EdDSA uses the left 32 bytes of SHA-512.
            'at_hash' => 'Sekkp6VYx0J5JzM6wSDG2BCgoNN3_3xGRmAYQteXZRo',
            'iat' => time() - 1,
            'exp' => time() + 299,
            'urn:identity-platform:application' => 'app-demo',
        ];
    }

    public function token(array $claims, ?string $secret = null, array $header = []): string
    {
        $protected = self::base64url(json_encode(array_replace(['alg' => 'EdDSA', 'kid' => 'test-ed25519', 'typ' => 'JWT'], $header), JSON_THROW_ON_ERROR));
        $payload = self::base64url(json_encode($claims, JSON_THROW_ON_ERROR));
        $unsigned = $protected.'.'.$payload;

        return $unsigned.'.'.self::base64url(sodium_crypto_sign_detached($unsigned, $secret ?? $this->secretKey));
    }

    public function fake(): void
    {
        Http::preventStrayRequests();
        Http::fake(function (Request $request) {
            $this->requests[] = $request;
            if ($request->url() === self::ISSUER.'/.well-known/openid-configuration') {
                return Http::response($this->metadata);
            }
            if ($request->url() === self::ISSUER.'/jwks') {
                return Http::response(['keys' => [[
                    'kid' => 'test-ed25519', 'kty' => 'OKP', 'crv' => 'Ed25519',
                    'x' => self::base64url($this->publicKey), 'use' => 'sig', 'alg' => 'EdDSA',
                ]]]);
            }
            if ($request->url() === self::ISSUER.'/oauth2/token') {
                if ($this->tokenDelayMicroseconds > 0) {
                    usleep($this->tokenDelayMicroseconds);
                }
                if ($this->tokenStatus !== 200) {
                    return Http::response(['error' => $this->tokenStatus === 400 ? 'invalid_grant' : 'invalid_client'], $this->tokenStatus);
                }
                parse_str($request->body(), $form);
                $result = array_replace([
                    'access_token' => 'synthetic-access-token',
                    'token_type' => 'Bearer',
                    'expires_in' => 300,
                    'refresh_token' => ($form['grant_type'] ?? null) === 'refresh_token' ? 'synthetic-successor-refresh-token' : 'synthetic-refresh-token',
                ], $this->tokenOverrides);
                if (! $this->omitIdToken && ! ($this->omitRefreshIdToken && ($form['grant_type'] ?? null) === 'refresh_token')) {
                    $result['id_token'] = $this->rawIdToken ?? $this->token($this->claims);
                }

                return Http::response($result);
            }
            if ($request->url() === self::ISSUER.'/oauth2/userinfo') {
                return Http::response($this->userinfo, $this->userinfoStatus);
            }

            return Http::response(['error' => 'unexpected_test_endpoint'], 500);
        });
    }

    public function tokenForms(): array
    {
        return array_values(array_map(static function (Request $request) {
            parse_str($request->body(), $body);

            return $body;
        }, array_filter($this->requests, static fn (Request $request) => $request->url() === self::ISSUER.'/oauth2/token')));
    }

    private static function base64url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
