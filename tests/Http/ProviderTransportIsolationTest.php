<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Http;

use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request as PsrRequest;
use GuzzleHttp\Psr7\Uri;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Http;

/** Host-wide HTTP client configuration has no authority over provider requests. */
final class ProviderTransportIsolationTest extends TestCase
{
    public function test_ambient_retry_middleware_cannot_replay_a_provider_write(): void
    {
        $decisions = 0;
        Http::globalMiddleware(Middleware::retry(function (int $retries) use (&$decisions): bool {
            $decisions++;

            return $retries < 1;
        }, fn (): int => 0));
        $sends = 0;
        Http::fake(function () use (&$sends) {
            $sends++;

            return Http::response(['error' => 'server_error'], 503);
        });

        try {
            app(IdentityHttp::class)->form('/api/auth/oauth2/token', ['grant_type' => 'refresh_token', 'refresh_token' => 'synthetic-single-use']);
            self::fail('Provider failure was accepted');
        } catch (IdentityException $error) {
            self::assertSame(503, $error->status);
        }
        self::assertSame(1, $sends);
        self::assertSame(0, $decisions);
    }

    public function test_ambient_options_cannot_replace_client_credentials_or_add_cookies(): void
    {
        Http::globalOptions(['headers' => ['Cookie' => 'host-session=synthetic'], 'auth' => ['ambient-worker', 'ambient-secret']]);
        $observed = [];
        Http::fake(function ($request) use (&$observed) {
            $observed[] = $request;

            return Http::response(['active' => false]);
        });
        $http = app(IdentityHttp::class);
        $clientAuthentication = 'Basic '.base64_encode('web-1:secret');

        $http->sendPsr(new PsrRequest('POST', 'https://identity.test/api/auth/oauth2/token', ['Authorization' => $clientAuthentication, 'Content-Type' => 'application/x-www-form-urlencoded'], 'grant_type=refresh_token'));
        $http->get('/api/auth/.well-known/openid-configuration');

        self::assertCount(2, $observed);
        self::assertTrue($observed[0]->hasHeader('Authorization', $clientAuthentication));
        self::assertFalse($observed[1]->hasHeader('Authorization'));
        foreach ($observed as $request) {
            self::assertFalse($request->hasHeader('Cookie'));
        }
        // Ordinary host callers keep their own configuration.
        self::assertSame(['ambient-worker', 'ambient-secret'], Http::createPendingRequest()->getOptions()['auth']);
    }

    public function test_ambient_request_middleware_cannot_move_provider_credentials_to_another_host(): void
    {
        $calls = 0;
        Http::globalRequestMiddleware(function ($request) use (&$calls) {
            $calls++;

            return $request->withUri(new Uri('https://ambient.test'.$request->getUri()->getPath()));
        });
        $observed = [];
        Http::fake(function ($request) use (&$observed) {
            $observed[] = $request->url();

            return Http::response('{}');
        });

        app(IdentityHttp::class)->form('/api/auth/oauth2/revoke', ['token' => 'synthetic-token', 'token_type_hint' => 'access_token']);

        self::assertSame(['https://identity.test/api/auth/oauth2/revoke'], $observed);
        self::assertSame(0, $calls);
    }
}
