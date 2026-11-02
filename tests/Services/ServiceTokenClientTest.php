<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Services;

use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Services\ServiceTokenManager;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

final class ServiceTokenClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->configure(['identity.service_targets.reports.origin' => 'https://identity.test']);
        $this->configure(['identity.service_targets.reports.application_id' => 'app-1']);
        $this->configure(['identity.service_targets.reports.client_id' => 'worker-1']);
        $this->configure(['identity.service_targets.reports.client_secret' => 'service-secret']);
        $this->configure(['identity.service_targets.reports.scopes' => ['documents.read', 'documents.write']]);
        Cache::flush();
        Http::preventStrayRequests();
    }

    public function test_client_credentials_uses_machine_issuer_resource_and_shared_scope_bound_cache(): void
    {
        Http::fakeSequence()->push($this->tokenResponse('synthetic-first'))->push($this->tokenResponse('synthetic-second', 'documents.write'));
        $client = app(ServiceTokenManager::class)->target('reports');
        self::assertSame('synthetic-first', $client->token(['documents.read']));
        self::assertSame('synthetic-first', (app(ServiceTokenManager::class)->target('reports'))->token(['documents.read']));
        self::assertSame('synthetic-second', $client->token(['documents.write']));
        Http::assertSentCount(2);
        Http::assertSent(fn ($request) => $request->url() === 'https://identity.test/api/service-auth/oauth2/token'
            && $request->hasHeader('Authorization', 'Basic '.base64_encode('worker-1:service-secret'))
            && $request['grant_type'] === 'client_credentials' && $request['resource'] === 'urn:identity-platform:application:app-1');
    }

    #[DataProvider('invalidTokens')]
    public function test_malformed_or_excess_authority_token_response_is_not_cached(string $field, mixed $value): void
    {
        Http::fake(['*' => Http::response(array_replace($this->tokenResponse(), [$field => $value]))]);
        $this->expectException(IdentityException::class);
        app(ServiceTokenManager::class)->target('reports')->token(['documents.read']);
    }

    public static function invalidTokens(): array
    {
        return [['access_token', ''], ['access_token', "unsafe\r\ntoken"], ['access_token', str_repeat('a', 60001)], ['unknown', 'forbidden'], ['scope', null], ['token_type', 'Basic'], ['expires_in', 301], ['expires_in', 0], ['expires_in', '300'], ['scope', 'documents.write'], ['refresh_token', 'forbidden'], ['id_token', 'forbidden']];
    }

    public function test_interactive_scopes_are_refused_before_contacting_the_provider(): void
    {
        try {
            app(ServiceTokenManager::class)->target('reports')->token(['openid']);
            self::fail('Interactive scope was accepted');
        } catch (IdentityException) {
            Http::assertNothingSent();
        }
    }

    public function test_worker_secret_failure_is_an_operator_failure_and_never_a_cached_token(): void
    {
        Http::fake(['*' => Http::response(['error' => 'invalid_client'], 401)]);
        try {
            app(ServiceTokenManager::class)->target('reports')->token(['documents.read']);
            self::fail('Invalid worker credentials were accepted');
        } catch (IdentityException $error) {
            self::assertSame(503, $error->status);
            self::assertSame('service_authentication_failed', $error->errorCode);
        }
    }

    public function test_response_scope_rejection_is_a_bad_upstream_response(): void
    {
        Http::fake(['*' => Http::response($this->tokenResponse(scope: 'openid'))]);
        try {
            app(ServiceTokenManager::class)->target('reports')->token(['documents.read']);
            self::fail('Interactive response scope was accepted');
        } catch (IdentityException $error) {
            self::assertSame(502, $error->status);
            self::assertSame('invalid_service_token_response', $error->errorCode);
        }
    }

    public function test_revocation_uses_issuing_worker_and_evicts_its_cached_token(): void
    {
        Http::fakeSequence()->push($this->tokenResponse('synthetic-first'))->push('{}')->push($this->tokenResponse('synthetic-new'));
        $client = app(ServiceTokenManager::class)->target('reports');
        $client->revoke($client->token(['documents.read']));
        self::assertSame('synthetic-new', $client->token(['documents.read']));
        Http::assertSent(fn ($request) => $request->url() === 'https://identity.test/api/service-auth/oauth2/revoke' && $request['token'] === 'synthetic-first');
    }

    public function test_rejected_token_eviction_is_scope_bound_and_never_revokes_remotely(): void
    {
        Http::fakeSequence()->push($this->tokenResponse('synthetic-read'))->push($this->tokenResponse('synthetic-write', 'documents.write'))->push($this->tokenResponse('synthetic-fresh-read'));
        $client = app(ServiceTokenManager::class)->target('reports');
        $read = $client->token(['documents.read']);
        $write = $client->token(['documents.write']);

        $client->reject($read, ['documents.write']);
        self::assertSame($write, $client->token(['documents.write']));
        $client->reject($read, ['documents.read']);
        self::assertSame('synthetic-fresh-read', $client->token(['documents.read']));
        self::assertSame($write, $client->token(['documents.write']));
        Http::assertSentCount(3);
        Http::assertNotSent(fn ($request) => $request->url() !== 'https://identity.test/api/service-auth/oauth2/token');
    }

    public function test_late_rejection_of_predecessor_cannot_evict_cached_successor(): void
    {
        Http::fakeSequence()->push($this->tokenResponse('synthetic-predecessor'))->push($this->tokenResponse('synthetic-successor'));
        $client = app(ServiceTokenManager::class)->target('reports');
        $predecessor = $client->token(['documents.read']);
        $client->reject($predecessor, ['documents.read']);
        $successor = $client->token(['documents.read']);

        $client->reject($predecessor, ['documents.read']);

        self::assertSame($successor, $client->token(['documents.read']));
        Http::assertSentCount(2);
    }

    public static function overlayStatuses(): array
    {
        return ['pending' => ['pending'], 'active' => ['active']];
    }

    #[DataProvider('overlayStatuses')]
    public function test_delegated_browser_cannot_reject_cached_machine_credential(string $status): void
    {
        Http::fakeSequence()->push($this->tokenResponse('synthetic-cached'));
        $client = app(ServiceTokenManager::class)->target('reports');
        $token = $client->token(['documents.read']);
        $overlays = app(OverlayRepository::class);
        $overlays->save('delegated-browser', ['source_sid' => 'central-session', 'status' => $status, 'browser_binding' => str_repeat('b', 43), 'context_version' => 2, 'expires_at' => now()->addMinutes(5)]);
        $browser = Request::create('https://consumer.test/');
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        $store->put('identity.session', 'delegated-browser');
        $browser->setLaravelSession($store);
        $this->bindRequest($browser);

        try {
            $client->reject($token, ['documents.read']);
            self::fail('A delegated browser evicted a machine credential');
        } catch (IdentityException $error) {
            self::assertSame('delegation_outbound_forbidden', $error->errorCode);
            self::assertSame(403, $error->status);
        }
        $overlays->stop('delegated-browser');
        self::assertSame($token, $client->token(['documents.read']));
        Http::assertSentCount(1);
    }

    public function test_token_that_expires_during_network_transit_is_refused(): void
    {
        Http::fake(function () {
            usleep(1100000);

            return Http::response(array_replace($this->tokenResponse(), ['expires_in' => 1]));
        });
        $this->expectException(IdentityException::class);
        app(ServiceTokenManager::class)->target('reports')->token(['documents.read']);
    }

    private function tokenResponse(string $token = 'synthetic-access', string $scope = 'documents.read'): array
    {
        return ['access_token' => $token, 'token_type' => 'Bearer', 'expires_in' => 300, 'scope' => $scope];
    }
}
