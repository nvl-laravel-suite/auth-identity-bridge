<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Services;

use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response as PsrResponse;
use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\TransferStats;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Services\ServiceTokenManager;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

final class ServiceTargetHttpTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Http::preventStrayRequests();
    }

    public function test_fixed_base_query_bearer_and_binary_response_without_worker_credentials(): void
    {
        Http::fake(['https://identity.test/*' => Http::response($this->token()), 'https://consumer.test/*' => Http::response("\0payload", 201)]);
        $response = app(ServiceTokenManager::class)->target('reports')->request('documents/1?format=a%20b', ['method' => 'POST', 'headers' => ['Content-Type' => 'application/json'], 'body' => '{}']);
        self::assertSame(201, $response->getStatusCode());
        self::assertSame("\0payload", (string) $response->getBody());
        Http::assertSent(fn ($request) => $request->url() === 'https://consumer.test/api/documents/1?format=a%20b'
            && $request->hasHeader('Authorization', 'Bearer synthetic-service') && ! $request->hasHeader('Cookie') && $request->body() === '{}');
        Http::assertSent(fn ($request) => $request->url() === 'https://identity.test/api/service-auth/oauth2/token' && $request->hasHeader('Authorization', 'Basic '.base64_encode('worker-1:service-secret')));
        Http::assertSentCount(2);
    }

    public function test_downstream_transport_disables_cookies_redirects_and_bounds_timeout(): void
    {
        Http::fake(function ($request, $options) {
            if (str_starts_with($request->url(), 'https://identity.test/')) {
                return Http::response($this->token());
            }
            self::assertFalse($options['cookies']);
            self::assertFalse($options['allow_redirects']);
            self::assertTrue($options['verify']);
            self::assertSame(5, $options['timeout']);
            self::assertSame(3, $options['connect_timeout']);
            self::assertSame(5, $options['read_timeout']);
            self::assertTrue($options['stream']);
            self::assertArrayNotHasKey('auth', $options);

            return Http::response('ok');
        });
        self::assertSame('ok', (string) app(ServiceTokenManager::class)->target('reports')->request('documents')->getBody());
    }

    public function test_ambient_options_cannot_supply_cookies_host_or_override_target_credentials(): void
    {
        Http::globalOptions(['headers' => ['Cookie' => 'host-session=synthetic', 'Host' => 'ambient.test', 'Authorization' => 'Bearer ambient-token'], 'auth' => ['ambient-worker', 'ambient-secret']]);
        $observed = [];
        Http::fake(function ($request, $options) use (&$observed) {
            $observed[] = [$request, $options];

            return Http::response(str_contains($request->url(), '/oauth2/token') ? $this->token() : 'created', 201);
        });
        $response = app(ServiceTokenManager::class)->target('reports')->request('documents', ['method' => 'POST', 'body' => '{}']);
        self::assertSame(201, $response->getStatusCode());
        self::assertCount(2, $observed);
        foreach ($observed as [$request]) {
            self::assertFalse($request->hasHeader('Cookie'));
            self::assertFalse($request->hasHeader('Host', 'ambient.test'));
        }
        self::assertTrue($observed[0][0]->hasHeader('Authorization', 'Basic '.base64_encode('worker-1:service-secret')));
        self::assertTrue($observed[1][0]->hasHeader('Authorization', 'Bearer synthetic-service'));
        self::assertArrayNotHasKey('auth', $observed[1][1]);
        // Creating the isolated pending requests must leave ordinary host callers unchanged.
        self::assertSame(['ambient-worker', 'ambient-secret'], Http::createPendingRequest()->getOptions()['auth']);
        Http::assertSentCount(2);
    }

    public function test_ambient_request_middleware_cannot_change_issuance_or_business_destination(): void
    {
        $middlewareCalls = 0;
        Http::globalRequestMiddleware(function ($request) use (&$middlewareCalls) {
            $middlewareCalls++;

            return $request->withUri(new Uri('https://ambient.test'.$request->getUri()->getPath()))->withHeader('Cookie', 'host-session=synthetic');
        });
        $observed = [];
        Http::fake(function ($request) use (&$observed) {
            $observed[] = $request->url();

            return Http::response(str_contains($request->url(), '/oauth2/token') ? $this->token() : 'created', 201);
        });
        $response = app(ServiceTokenManager::class)->target('reports')->request('documents', ['method' => 'POST', 'body' => '{}']);
        self::assertSame(201, $response->getStatusCode());
        self::assertSame(0, $middlewareCalls);
        self::assertSame(['https://identity.test/api/service-auth/oauth2/token', 'https://consumer.test/api/documents'], $observed);
        self::assertCount(1, Http::getGlobalMiddleware());
    }

    public function test_ambient_retry_middleware_cannot_replay_provider_or_business_requests(): void
    {
        $decisions = 0;
        Http::globalMiddleware(Middleware::retry(function ($retries) use (&$decisions) {
            $decisions++;

            return $retries < 1;
        }, fn () => 0));
        $providerSends = 0;
        $businessSends = 0;
        Http::fake(function ($request) use (&$providerSends, &$businessSends) {
            if (str_contains($request->url(), '/oauth2/token')) {
                $providerSends++;

                return Http::response($this->token());
            }
            $businessSends++;

            return Http::response('domain failed after possible commit', 503);
        });
        $response = app(ServiceTokenManager::class)->target('reports')->request('documents', ['method' => 'POST', 'body' => '{}']);
        self::assertSame(503, $response->getStatusCode());
        self::assertSame(0, $decisions);
        self::assertSame(1, $providerSends);
        self::assertSame(1, $businessSends);
    }

    #[DataProvider('canonicalDestinations')]
    public function test_canonical_uri_with_populated_transfer_stats_returns_success_once(string $base, string $path, string $expected): void
    {
        $this->configure(['identity.service_targets.reports.base_url' => $base]);
        $businessUris = [];
        Http::fake(function ($request, $options) use (&$businessUris) {
            if (str_contains($request->url(), '/oauth2/token')) {
                return Http::response($this->token());
            }
            $businessUris[] = $request->url();
            $options['on_stats'](new TransferStats($request->toPsrRequest(), new PsrResponse(201), 0.001));

            return Http::response('committed', 201);
        });
        $response = app(ServiceTokenManager::class)->target('reports')->request($path, ['method' => 'POST', 'body' => '{}']);
        self::assertSame(201, $response->getStatusCode());
        self::assertSame('committed', (string) $response->getBody());
        self::assertSame([$expected], $businessUris);
        Http::assertSentCount(2);
    }

    public static function canonicalDestinations(): array
    {
        return [
            ['https://consumer.test:443/api', 'documents', 'https://consumer.test/api/documents'],
            ['https://CONSUMER.TEST/api', 'documents', 'https://consumer.test/api/documents'],
            ['https://consumer.test/api', 'documents?filter[id]=123', 'https://consumer.test/api/documents?filter%5Bid%5D=123'],
            ['https://CONSUMER.TEST:443/api/', 'documents?filter[id]=a%20b&next=%2Fpath', 'https://consumer.test/api/documents?filter%5Bid%5D=a%20b&next=%2Fpath'],
            ['https://consumer.test:8443/api', 'documents', 'https://consumer.test:8443/api/documents'],
        ];
    }

    public function test_effective_uri_escape_still_refuses_with_populated_transfer_stats(): void
    {
        Http::fake(function ($request, $options) {
            if (str_contains($request->url(), '/oauth2/token')) {
                return Http::response($this->token());
            }
            $effective = $request->toPsrRequest()->withUri(new Uri('https://other.test/escape'));
            $options['on_stats'](new TransferStats($effective, new PsrResponse(201), 0.001));

            // An array fake avoids Factory::fake replacing our populated stats.
            return ['unexpected' => true];
        });
        try {
            app(ServiceTokenManager::class)->target('reports')->request('documents', ['method' => 'POST', 'body' => '{}']);
            self::fail('Unexpected effective URI accepted');
        } catch (IdentityException $error) {
            self::assertSame('untrusted_endpoint', $error->errorCode);
            Http::assertSentCount(2);
        }
    }

    #[DataProvider('invalidRequests')]
    public function test_unsafe_destination_or_options_fail_before_token_cache_or_http(string $path, array $options): void
    {
        try {
            app(ServiceTokenManager::class)->target('reports')->request($path, $options);
            self::fail('Unsafe request accepted');
        } catch (IdentityException $error) {
            self::assertContains($error->errorCode, ['invalid_service_destination', 'invalid_service_request', 'service_scope_invalid']);
            Http::assertNothingSent();
            self::assertSame([], Cache::store('array')->getStore()->all());
        }
    }

    public static function invalidRequests(): array
    {
        $cases = [];
        foreach (['', '/escape', '//other.test/x', 'https://other.test/x', 'https://user:pass@other.test/x', '../escape', 'x/../escape', 'x/./y', 'x//y', 'x\\y', 'x#fragment', '%2e%2e/x', 'x%2fy', 'x%252fy', "x\n", 'x?a=%zz'] as $path) {
            $cases[] = [$path, []];
        }
        foreach (['Authorization', 'aUtHoRiZaTiOn', 'Cookie', 'Cookie2', 'Host', 'Origin', 'Referer', 'Proxy-Authorization', 'Sec-Fetch-Site', 'Connection', 'Content-Length', 'X-Forwarded-Host'] as $header) {
            $cases[] = ['documents', ['headers' => [$header => 'forbidden']]];
        }

        return [...$cases, ['x', ['headers' => ['X-Test' => "a\r\nb"]]], ['x', ['headers' => ['X-Test' => str_repeat('a', 16384)]]], ['x', ['headers' => ['X-Test' => 'a', 'x-test' => 'b']]], ['x', ['headers' => ['x' => ['a']]]], ['x', ['body' => 'data']], ['x', ['method' => 'TRACE']], ['x', ['method' => 'POST', 'body' => str_repeat('a', 65537)]], ['x', ['scopes' => []]], ['x', ['scopes' => ['documents.write']]], ['x', ['allow_redirects' => true]]];
    }

    public function test_redirect_is_refused_without_following_or_replaying_write(): void
    {
        Http::fakeSequence()->push($this->token())->push('', 307, ['Location' => 'https://other.test/steal']);
        try {
            app(ServiceTokenManager::class)->target('reports')->request('documents', ['method' => 'POST', 'body' => '{}']);
            self::fail('Redirect accepted');
        } catch (IdentityException $error) {
            self::assertSame('redirect_refused', $error->errorCode);
            Http::assertSentCount(2);
        }
    }

    public function test_response_size_is_bounded(): void
    {
        Http::fakeSequence()->push($this->token())->push(str_repeat('a', 131073));
        try {
            app(ServiceTokenManager::class)->target('reports')->request('documents');
            self::fail('Oversize accepted');
        } catch (IdentityException $error) {
            self::assertSame('response_too_large', $error->errorCode);
            Http::assertSentCount(2);
        }
    }

    #[DataProvider('domainFailures')]
    public function test_domain_failure_is_returned_without_auth_retry_or_write_replay(int $status): void
    {
        Http::fakeSequence()->push($this->token())->push('domain error', $status);
        $response = app(ServiceTokenManager::class)->target('reports')->request('documents', ['method' => 'POST', 'body' => '{}']);
        self::assertSame($status, $response->getStatusCode());
        Http::assertSentCount(2);
    }

    public static function domainFailures(): array
    {
        return [[401], [403], [409], [500], [503]];
    }

    public function test_ambiguous_transport_failure_is_sanitized_and_not_replayed(): void
    {
        $calls = 0;
        Http::fake(function ($request) use (&$calls) {
            $calls++;
            if (str_starts_with($request->url(), 'https://identity.test/')) {
                return Http::response($this->token());
            }
            throw new \RuntimeException('private downstream diagnostic');
        });
        try {
            app(ServiceTokenManager::class)->target('reports')->request('documents', ['method' => 'POST', 'body' => '{}']);
            self::fail('Transport failure accepted');
        } catch (IdentityException $error) {
            self::assertSame('transport_unavailable', $error->errorCode);
            self::assertNull($error->getPrevious());
            self::assertSame(2, $calls);
        }
    }

    private function token(): array
    {
        return ['access_token' => 'synthetic-service', 'token_type' => 'Bearer', 'expires_in' => 300, 'scope' => 'documents.read'];
    }
}
