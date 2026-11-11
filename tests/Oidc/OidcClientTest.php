<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Oidc;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Oidc\OidcClient;
use IdentityPlatform\Laravel\Oidc\TrustedProviderMetadata;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

final class OidcClientTest extends TestCase
{
    private ProviderFixture $provider;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('identity.consumers.one.origin', ProviderFixture::ORIGIN);
        $app['config']->set('identity.consumers.one.application_id', 'app-demo');
        $app['config']->set('identity.consumers.one.app_origin', 'https://laravel.example.test');
        $app['config']->set('identity.consumers.one.browser', ['client_id' => 'web-demo', 'client_secret' => 'synthetic-browser-client-secret', 'redirect_uri' => 'https://laravel.example.test/auth/callback', 'post_logout_redirect_uri' => 'https://laravel.example.test/signed-out', 'id_token_algorithm' => 'EdDSA']);
        $app['config']->set('identity.consumers.one.routes.event_uri', 'https://laravel.example.test/identity/events');
        $app['config']->set('identity.consumers.one.routes.backchannel_logout_uri', 'https://laravel.example.test/auth/backchannel-logout');
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->provider = new ProviderFixture;
        $this->provider->fake();
    }

    public function test_authorization_uses_server_owned_pkce_nonce_and_fixed_resource(): void
    {
        $url = $this->app->make(OidcClient::class)->authorization($this->intent());
        self::assertSame(ProviderFixture::ISSUER.'/oauth2/authorize', strtok($url, '?'));
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        self::assertSame('web-demo', $query['client_id']);
        self::assertSame('code', $query['response_type']);
        self::assertSame('https://laravel.example.test/auth/callback', $query['redirect_uri']);
        self::assertSame('openid profile email offline_access', $query['scope']);
        self::assertSame('synthetic-state', $query['state']);
        self::assertSame('synthetic-nonce', $query['nonce']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', $query['code_challenge']);
        self::assertSame('urn:identity-platform:application:app-demo', $query['resource']);
        self::assertArrayNotHasKey('code_verifier', $query);
        self::assertArrayNotHasKey('client_secret', $query);
    }

    public function test_long_lived_client_observes_discovery_expiry_before_authorization(): void
    {
        $client = $this->app->make(OidcClient::class);
        $client->authorization($this->intent());
        $this->travel(301)->seconds();
        $this->provider->metadata['authorization_endpoint'] = ProviderFixture::ISSUER.'/oauth2/new-authorize';

        self::assertSame(ProviderFixture::ISSUER.'/oauth2/new-authorize', strtok($client->authorization($this->intent()), '?'));
        Http::assertSentCount(2);
    }

    public function test_separate_oidc_clients_share_discovery_and_keys_without_caching_token_or_userinfo_calls(): void
    {
        self::assertSame('person-demo', $this->exchange()['subject']);
        self::assertSame('person-demo', $this->exchange()['subject']);
        Http::assertSentCount(6);
        self::assertCount(2, $this->provider->tokenForms());
    }

    public function test_code_exchange_verifies_real_ed25519_id_token_and_matching_userinfo(): void
    {
        $before = time();
        $tokens = $this->exchange();
        self::assertSame('person-demo', $tokens['subject']);
        self::assertSame('central-session-demo', $tokens['sid']);
        self::assertSame('Synthetic Person', $tokens['userinfo']['name']);
        self::assertSame('app-demo', $tokens['claims']['urn:identity-platform:application']);
        self::assertSame('synthetic-access-token', $tokens['access_token']);
        self::assertSame('synthetic-refresh-token', $tokens['refresh_token']);
        self::assertTrue($tokens['resource']);
        self::assertLessThanOrEqual($before + 300, $tokens['expires_at']);
        self::assertSame($this->provider->claims['exp'], $tokens['expires_at']);
        $forms = $this->provider->tokenForms();
        self::assertSame([
            'grant_type' => 'authorization_code',
            'code' => 'synthetic-code',
            'redirect_uri' => 'https://laravel.example.test/auth/callback',
            'code_verifier' => $this->intent()['verifier'],
            'resource' => 'urn:identity-platform:application:app-demo',
        ], $forms[0]);
        Http::assertSent(fn ($request) => $request->url() === ProviderFixture::ISSUER.'/oauth2/userinfo' && $request->hasHeader('Authorization', 'Bearer synthetic-access-token'));
    }

    public function test_ordinary_login_never_adds_a_resource_profile(): void
    {
        $tokens = $this->app->make(OidcClient::class)->exchange(['code' => 'synthetic-code', 'state' => 'synthetic-state'], $this->intent(false));
        self::assertFalse($tokens['resource']);
        self::assertArrayNotHasKey('resource', $this->provider->tokenForms()[0]);
        $this->app->make(OidcClient::class)->refresh($tokens);
        self::assertArrayNotHasKey('resource', $this->provider->tokenForms()[1]);
    }

    public function test_refresh_rotates_tokens_and_preserves_subject_sid_and_resource(): void
    {
        $client = $this->app->make(OidcClient::class);
        $tokens = $this->exchange();
        $this->provider->omitRefreshIdToken = true;
        $refreshed = $client->refresh($tokens);
        self::assertSame('synthetic-successor-refresh-token', $refreshed['refresh_token']);
        self::assertSame($tokens['id_token'], $refreshed['id_token']);
        self::assertSame($tokens['subject'], $refreshed['subject']);
        self::assertSame($tokens['sid'], $refreshed['sid']);
        self::assertTrue($refreshed['resource']);
        self::assertSame([
            'resource' => 'urn:identity-platform:application:app-demo',
            'grant_type' => 'refresh_token',
            'refresh_token' => 'synthetic-refresh-token',
        ], $this->provider->tokenForms()[1]);
    }

    public function test_native_eddsa_token_hashes_are_verified_during_exchange_and_refresh(): void
    {
        $this->provider->claims['s_hash'] = '2Tw6JCY9J6IaA7pmK_62ACroYIGI99Wrr01P3coSu9Y';
        $this->provider->claims['c_hash'] = '256LYSBgrYqfnywEO9pZwy-5sXnEnDWgnPhK6xVNoFg';
        $tokens = $this->exchange();
        self::assertSame('person-demo', $tokens['subject']);
        unset($this->provider->claims['s_hash'], $this->provider->claims['c_hash']);
        self::assertSame('person-demo', $this->app->make(OidcClient::class)->refresh($tokens)['subject']);
    }

    public function test_refresh_access_lifetime_starts_before_network_wait_without_capping_to_old_id_expiry(): void
    {
        $tokens = $this->exchange();
        $tokens['claims']['exp'] = time() - 1;
        $this->provider->omitRefreshIdToken = true;
        $this->provider->tokenDelayMicroseconds = 1_100_000;
        $before = time();
        $refreshed = $this->app->make(OidcClient::class)->refresh($tokens);
        self::assertLessThanOrEqual($before + 300, $refreshed['expires_at']);
        self::assertGreaterThan($before + 290, $refreshed['expires_at']);
    }

    public function test_refresh_rejects_malformed_prior_claims_when_provider_omits_new_id_token(): void
    {
        $tokens = $this->exchange();
        $tokens['claims']['exp'] = 'not-an-integer-deadline';
        $this->provider->omitRefreshIdToken = true;

        $this->expectExceptionObject(new IdentityException('oidc_token_invalid', 401));
        $this->app->make(OidcClient::class)->refresh($tokens);
    }

    public function test_cached_jwks_rejects_scalar_key_entries_before_library_consumption(): void
    {
        Cache::store('identity_tests')->put('identity-oidc:'.hash('sha256', ProviderFixture::ISSUER).':jwks', ['keys' => ['invalid-key']], 300);

        $this->expectExceptionObject(new IdentityException('oidc_keys_invalid', 502));
        $this->app->make(TrustedProviderMetadata::class)->getJwks();
    }

    #[DataProvider('invalidEdDsaHashes')]
    public function test_signed_eddsa_hash_mismatch_is_rejected(string $claim, string $value): void
    {
        $this->provider->claims[$claim] = $value;
        $this->expectExceptionObject(new IdentityException('oidc_token_hash_invalid', 401));
        $this->exchange();
    }

    public static function invalidEdDsaHashes(): array
    {
        return [
            'wrong SHA256 access hash' => ['at_hash', 'F30iRba6HrejUQBwrzD-Rg'],
            'altered access hash' => ['at_hash', 'Aekkp6VYx0J5JzM6wSDG2BCgoNN3_3xGRmAYQteXZRo'],
            'wrong state hash' => ['s_hash', 'uIBm-NPVrwBK0nU4OQf8kA'],
            'wrong code hash' => ['c_hash', 'Y_UhDntRhFwyNC5pA4H0wg'],
        ];
    }

    #[DataProvider('invalidClaims')]
    public function test_exchange_rejects_invalid_signed_claim_binding(string $claim, mixed $value): void
    {
        if ($value === '__missing__') {
            unset($this->provider->claims[$claim]);
        } else {
            $this->provider->claims[$claim] = $value;
        }
        $this->expectException(IdentityException::class);
        $this->exchange();
    }

    public static function invalidClaims(): array
    {
        return [
            'foreign issuer' => ['iss', 'https://foreign.example.test/api/auth'],
            'foreign audience' => ['aud', 'foreign-client'],
            'missing nonce' => ['nonce', '__missing__'],
            'wrong nonce' => ['nonce', 'wrong-nonce'],
            'missing sid' => ['sid', '__missing__'],
            'empty sid' => ['sid', ''],
            'empty subject' => ['sub', ''],
            'foreign application' => ['urn:identity-platform:application', 'foreign-app'],
            'null application claim' => ['urn:identity-platform:application', null],
            'foreign authorized party' => ['azp', 'foreign-client'],
            'null authorized party' => ['azp', null],
            'multiple audiences without azp' => ['aud', ['web-demo', 'other-client']],
            'expired' => ['exp', 1],
            'issued in the future' => ['iat', 4102444800],
        ];
    }

    public function test_exchange_rejects_forged_signature_with_correct_looking_claims(): void
    {
        $forgedKey = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
        $this->provider->rawIdToken = $this->provider->token($this->provider->claims, $forgedKey);
        $this->expectException(IdentityException::class);
        $this->exchange();
    }

    public function test_exchange_rejects_unsigned_id_token(): void
    {
        $encode = static fn (array $value) => rtrim(strtr(base64_encode(json_encode($value, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $this->provider->rawIdToken = $encode(['alg' => 'none']).'.'.$encode($this->provider->claims).'.';
        $this->expectException(IdentityException::class);
        $this->exchange();
    }

    public function test_foreign_signature_algorithms_are_invalid_tokens_not_provider_outages(): void
    {
        $encode = static fn (string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
        $publicKey = (string) base64_decode(strtr($this->app->make(TrustedProviderMetadata::class)->getJwks()['keys'][0]['x'], '-_', '+/'), true);
        self::assertSame(32, strlen($publicKey));
        $payload = $encode(json_encode($this->provider->claims, JSON_THROW_ON_ERROR));
        $symmetric = $encode(json_encode(['alg' => 'HS256', 'kid' => 'test-ed25519', 'typ' => 'JWT'], JSON_THROW_ON_ERROR)).'.'.$payload;
        $forged = [
            'HS256 keyed by the client secret' => $symmetric.'.'.$encode(hash_hmac('sha256', $symmetric, 'synthetic-browser-client-secret', true)),
            'HS256 keyed by the published public key' => $symmetric.'.'.$encode(hash_hmac('sha256', $symmetric, $publicKey, true)),
            'unsigned' => $encode(json_encode(['alg' => 'none', 'typ' => 'JWT'], JSON_THROW_ON_ERROR)).'.'.$payload.'.',
            'headerless' => 'not-a-header.'.$payload.'.',
        ];
        foreach ($forged as $name => $token) {
            $this->provider->rawIdToken = $token;
            try {
                $this->exchange();
                self::fail($name.' was accepted for an asymmetric client');
            } catch (IdentityException $error) {
                self::assertSame('oidc_token_invalid', $error->errorCode, $name);
                self::assertSame(401, $error->status, $name);
            }
        }
    }

    public function test_unknown_key_id_refetches_keys_once_within_the_refresh_window(): void
    {
        $this->provider->rawIdToken = $this->provider->token($this->provider->claims, header: ['kid' => 'rotated-away']);
        for ($attempt = 0; $attempt < 3; $attempt++) {
            try {
                $this->exchange();
                self::fail('A token for an unpublished key was accepted');
            } catch (IdentityException $error) {
                self::assertSame('oidc_token_invalid', $error->errorCode);
            }
        }

        self::assertCount(2, array_filter($this->provider->requests, static fn ($request): bool => $request->url() === ProviderFixture::ISSUER.'/jwks'));
    }

    public function test_exchange_requires_actual_id_token(): void
    {
        $this->provider->omitIdToken = true;
        $this->expectException(IdentityException::class);
        $this->exchange();
    }

    public function test_exchange_refuses_state_mismatch_before_token_request(): void
    {
        try {
            $this->app->make(OidcClient::class)->exchange(['code' => 'synthetic-code', 'state' => 'forged-state'], $this->intent());
            self::fail('State mismatch was accepted');
        } catch (IdentityException) {
            self::assertSame([], $this->provider->tokenForms());
        }
    }

    public function test_exchange_refuses_browser_supplied_implicit_tokens(): void
    {
        $this->expectException(IdentityException::class);
        $this->app->make(OidcClient::class)->exchange(['state' => 'synthetic-state', 'access_token' => 'synthetic-forged-browser-token'], $this->intent());
    }

    public function test_userinfo_subject_must_match_verified_identity(): void
    {
        $this->provider->userinfo['sub'] = 'another-person';
        $this->expectException(IdentityException::class);
        $this->exchange();
    }

    public function test_refresh_refuses_changed_central_session(): void
    {
        $tokens = $this->exchange();
        $this->provider->claims['sid'] = 'another-central-session';
        $this->expectException(IdentityException::class);
        $this->app->make(OidcClient::class)->refresh($tokens);
    }

    public function test_provider_client_auth_failure_is_sanitized_operator_failure(): void
    {
        $this->provider->tokenStatus = 401;
        try {
            $this->exchange();
            self::fail('Invalid provider client authentication was accepted');
        } catch (IdentityException $error) {
            self::assertSame(503, $error->status);
            self::assertSame('oidc_unavailable', $error->errorCode);
        }
    }

    public function test_provider_rate_limit_preserves_retryable_status(): void
    {
        $this->provider->tokenStatus = 429;
        try {
            $this->exchange();
            self::fail('Rate limited token exchange was accepted');
        } catch (IdentityException $error) {
            self::assertSame(429, $error->status);
        }
    }

    public function test_token_directed_jwks_url_is_never_used(): void
    {
        $this->provider->rawIdToken = $this->provider->token($this->provider->claims, header: ['jku' => 'https://foreign.example.test/jwks']);
        self::assertSame('person-demo', $this->exchange()['subject']);
        foreach ($this->provider->requests as $request) {
            self::assertStringStartsWith(ProviderFixture::ORIGIN.'/', $request->url());
        }
    }

    #[DataProvider('unsafeMetadata')]
    public function test_discovery_refuses_untrusted_endpoint_binding(string $key, string $value): void
    {
        $this->provider->metadata[$key] = $value;
        $this->expectException(IdentityException::class);
        $this->app->make(OidcClient::class)->metadata();
    }

    public static function unsafeMetadata(): array
    {
        return [
            ['issuer', 'https://foreign.example.test/api/auth'],
            ['token_endpoint', 'https://foreign.example.test/token'],
            ['jwks_uri', 'http://identity.example.test/jwks'],
            ['authorization_endpoint', 'https://user:password@identity.example.test/auth'],
            ['userinfo_endpoint', 'https://identity.example.test/userinfo#fragment'],
            ['end_session_endpoint', '//foreign.example.test/logout'],
        ];
    }

    public function test_logout_url_contains_no_identity_token_or_secret(): void
    {
        $url = $this->app->make(OidcClient::class)->centralLogoutUrl('synthetic-logout-state');
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        self::assertSame(ProviderFixture::ISSUER.'/oauth2/end-session', strtok($url, '?'));
        self::assertSame([
            'client_id' => 'web-demo',
            'post_logout_redirect_uri' => 'https://laravel.example.test/signed-out',
            'state' => 'synthetic-logout-state',
        ], $query);
    }

    private function exchange(): array
    {
        return $this->app->make(OidcClient::class)->exchange(['code' => 'synthetic-code', 'state' => 'synthetic-state'], $this->intent());
    }

    private function intent(bool $resource = true): array
    {
        return [
            'state' => 'synthetic-state',
            'nonce' => 'synthetic-nonce',
            'verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
            'resource' => $resource,
        ];
    }
}
