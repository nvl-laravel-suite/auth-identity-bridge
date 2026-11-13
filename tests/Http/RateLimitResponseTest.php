<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Http;

use GuzzleHttp\Psr7\Request as PsrRequest;
use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Authorization\AuthorizationClient;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Http\Middleware\ApiCredential;
use IdentityPlatform\Laravel\Http\Middleware\BrowserSafety;
use IdentityPlatform\Laravel\Oidc\OidcClient;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\Oidc\ProviderFixture;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Http\Client\Request as OutboundRequest;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;

class RateLimitResponseTest extends TestCase
{
    public static function authorizationOperations(): array
    {
        return ['contexts' => ['contexts'], 'snapshot' => ['snapshot']];
    }

    #[DataProvider('authorizationOperations')]
    public function test_ordinary_authorization_rate_limit_reaches_package_json_without_retry_or_private_body(string $operation): void
    {
        Http::fake(['*' => Http::response(['error' => ['code' => 'invalid_credentials', 'private' => 'private-upstream-details']], 429, ['Retry-After' => '60'])]);
        Route::get('/ordinary-authorization', fn () => app(AuthorizationClient::class)->{$operation}('synthetic-access-token', 'person-demo', 'sid-demo'));

        $response = $this->getJson('https://consumer.test/ordinary-authorization');

        $response->assertStatus(429)->assertExactJson(['error' => 'rate_limited'])->assertHeader('Retry-After', '60');
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        $this->assertSame('strict-origin', $response->headers->get('Referrer-Policy'));
        $this->assertStringNotContainsString('private-upstream-details', $response->getContent());
        Http::assertSentCount(1);
    }

    public static function retryHeaders(): array
    {
        return [
            'minimum' => ['1', 1], 'maximum' => ['3600', 3600], 'missing' => [null, null],
            'zero' => ['0', null], 'negative' => ['-1', null], 'fractional' => ['1.5', null],
            'oversized' => ['3601', null], 'overflow' => [str_repeat('9', 80), null],
            'date' => ['Wed, 28 Oct 2026 10:00:00 GMT', null], 'multiple' => ['1, 2', null],
        ];
    }

    #[DataProvider('retryHeaders')]
    public function test_rate_limit_retry_after_only_accepts_bounded_positive_delta_seconds(?string $header, ?int $expected): void
    {
        Http::fake(['*' => Http::response('not-json', 429, $header === null ? [] : ['Retry-After' => $header])]);
        try {
            app(IdentityHttp::class)->json('/api/authorization/snapshot', []);
            $this->fail('A rate-limited authorization call was accepted');
        } catch (IdentityException $error) {
            $this->assertSame('rate_limited', $error->errorCode);
            $this->assertSame(429, $error->status);
            $this->assertSame($expected, $error->retryAfter);
            $this->assertStringNotContainsString('not-json', $error->getMessage());
        }
        Http::assertSentCount(1);
    }

    public static function nativeTransports(): array
    {
        return ['form' => ['form'], 'bearer' => ['bearer'], 'oidc PSR' => ['psr'], 'oidc metadata' => ['metadata']];
    }

    #[DataProvider('nativeTransports')]
    public function test_native_outbound_rate_limit_keeps_status_and_retry_metadata(string $transport): void
    {
        Http::fake(['*' => Http::response([], 429, ['Retry-After' => '45'])]);
        $http = app(IdentityHttp::class);
        try {
            match ($transport) {
                'form' => $http->form('/api/auth/oauth2/introspect', ['token' => 'synthetic-access-token'], 'resource'),
                'bearer' => $http->bearer('/api/auth/oauth2/userinfo', 'synthetic-access-token'),
                'psr' => $http->sendPsr(new PsrRequest('POST', 'https://identity.test/api/auth/oauth2/token')),
                'metadata' => app(OidcClient::class)->metadata(),
            };
            $this->fail('A rate-limited native call was accepted');
        } catch (IdentityException $error) {
            $this->assertSame('rate_limited', $error->errorCode);
            $this->assertSame(429, $error->status);
            $this->assertSame(45, $error->retryAfter);
        }
        Http::assertSentCount(1);
    }

    public function test_browser_safety_preserves_retry_after_when_it_catches_identity_failure(): void
    {
        $response = app(BrowserSafety::class)->handle(Request::create('https://consumer.test/'), fn () => throw new IdentityException('rate_limited', 429, 30));

        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame(['error' => 'rate_limited'], json_decode($response->getContent(), true));
        $this->assertSame('30', $response->headers->get('Retry-After'));
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
    }

    public function test_package_renderer_preserves_retry_metadata_from_identity_exception(): void
    {
        Route::get('/native-rate-limit', fn () => throw new IdentityException('rate_limited', 429, 20));

        $this->getJson('https://consumer.test/native-rate-limit')->assertStatus(429)
            ->assertExactJson(['error' => 'rate_limited'])->assertHeader('Retry-After', '20');
    }

    public function test_wrong_authentication_is_still_a_401_without_rate_limit_metadata(): void
    {
        Http::fake(['*' => Http::response(['error' => ['code' => 'rate_limited']], 401, ['Retry-After' => '45'])]);
        try {
            app(IdentityHttp::class)->json('/api/authorization/contexts', []);
            $this->fail('Incorrect authentication was accepted');
        } catch (IdentityException $error) {
            $this->assertSame('upstream_rejected', $error->errorCode);
            $this->assertSame(401, $error->status);
            $this->assertNull($error->retryAfter);
        }
        Http::assertSentCount(1);
    }

    public static function nativeRetryHeaders(): array
    {
        return [
            'standard' => [['Retry-After' => '45'], 45],
            'native' => [['X-Retry-After' => '60'], 60],
            'invalid native' => [['X-Retry-After' => 'bad'], null],
            'multiple native' => [['X-Retry-After' => ['30', '60']], null],
            'oversized native' => [['X-Retry-After' => '3601'], null],
            'standard takes precedence' => [['Retry-After' => '45', 'X-Retry-After' => '60'], 45],
            'malformed standard prevents fallback' => [['Retry-After' => 'bad', 'X-Retry-After' => '60'], null],
            'empty standard prevents fallback' => [['Retry-After' => '', 'X-Retry-After' => '60'], null],
        ];
    }

    #[DataProvider('nativeRetryHeaders')]
    public function test_rate_limited_real_oidc_refresh_retains_session_and_vault_without_retry(array $headers, ?int $expectedRetry): void
    {
        $this->configure(['identity.consumers.one.origin' => ProviderFixture::ORIGIN, 'identity.consumers.one.application_id' => 'app-demo', 'identity.consumers.one.browser.client_id' => 'web-demo']);
        Http::fake(function (OutboundRequest $request) use ($headers) {
            return $request->url() === ProviderFixture::ISSUER.'/oauth2/token'
                ? Http::response(['error' => 'rate_limited'], 429, $headers) : null;
        });
        $provider = new ProviderFixture;
        $provider->fake();
        $user = app(UserSynchronizer::class)->sync($provider->userinfo);
        $id = 'rate-limited-session';
        $vault = app(IdentityVault::class)->seal(['access_token' => 'synthetic-access-token', 'refresh_token' => 'synthetic-refresh-token',
            'id_token' => $provider->token($provider->claims), 'claims' => $provider->claims, 'subject' => 'person-demo', 'sid' => 'central-session-demo', 'resource' => false, 'expires_at' => time() + 10], 'session:'.$id);
        $rows = app(SessionRepository::class);
        $rows->create(['id' => $id, 'user_id' => $user->id, 'subject' => 'person-demo', 'sid' => 'central-session-demo', 'token_vault' => $vault,
            'selection' => [], 'context_version' => 1, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $request = Request::create('https://consumer.test/account');
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        $store->put('identity.session', $id);
        $request->setLaravelSession($store);

        try {
            app(SessionManager::class)->current($request);
            $this->fail('A rate-limited refresh was accepted');
        } catch (IdentityException $error) {
            $this->assertSame('rate_limited', $error->errorCode);
            $this->assertSame(429, $error->status);
            $this->assertSame($expectedRetry, $error->retryAfter);
        }
        $current = $rows->find($id);
        $this->assertNotNull($current);
        $this->assertSame($id, $request->session()->get('identity.session'));
        $this->assertTrue(hash_equals($vault, $current->token_vault), 'Retryable refresh failure must preserve the synthetic vault');
        $this->assertSame(1, $current->token_generation);
        $this->assertCount(1, Http::recorded(fn (OutboundRequest $outbound) => $outbound->url() === ProviderFixture::ISSUER.'/oauth2/token'));
    }

    public function test_api_credential_middleware_preserves_retry_after_and_defensive_headers(): void
    {
        $request = Request::create('https://consumer.test/api/resource');
        $request->headers->set('Authorization', 'Bearer synthetic-token');
        Http::fake(['*' => Http::response(['error' => 'rate_limited'], 429, ['Retry-After' => '25'])]);

        $response = app(ApiCredential::class)->handle(
            $request,
            fn () => response()->json(['ok' => true]),
            'service_token',
        );

        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame(['error' => 'rate_limited'], json_decode((string) $response->getContent(), true));
        $this->assertSame('25', $response->headers->get('Retry-After'));
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        $this->assertSame('strict-origin', $response->headers->get('Referrer-Policy'));
        $this->assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }
}
