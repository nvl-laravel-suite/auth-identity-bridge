<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Services;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Services\ServiceTokenManager;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

final class ServiceTargetSafetyTest extends TestCase
{
    public function test_unconfigured_scope_is_denied_without_http_or_cache(): void
    {
        Http::preventStrayRequests();
        $client = app(ServiceTokenManager::class)->target('reports');
        try {
            $client->token(['documents.write']);
            self::fail('Unconfigured scope accepted');
        } catch (IdentityException $e) {
            self::assertSame('service_scope_invalid', $e->errorCode);
            Http::assertNothingSent();
            self::assertSame([], Cache::store('array')->getStore()->all());
        }
    }

    public function test_late_revocation_cannot_remove_a_successor(): void
    {
        $client = app(ServiceTokenManager::class)->target('reports');
        $issued = 0;
        $successor = null;
        Http::fake(function ($request) use ($client, &$issued, &$successor) {
            if (str_ends_with($request->url(), '/revoke')) {
                $client->reject('synthetic-old');
                $successor = $client->token();

                return Http::response('{}');
            }

            return Http::response($this->response(++$issued === 1 ? 'synthetic-old' : 'synthetic-new'));
        });
        $old = $client->token();
        $client->revoke($old);
        self::assertSame($successor, $client->token());
        Http::assertSentCount(3);
    }

    public function test_ciphertext_copied_between_scope_keys_cannot_authorize_reuse(): void
    {
        $this->configure(['identity.service_targets.reports.scopes' => ['documents.read', 'documents.write']]);
        Http::fakeSequence()->push($this->response('synthetic-read'))->push($this->response('synthetic-write', 'documents.write'))->push($this->response('synthetic-new-write', 'documents.write'));
        $client = app(ServiceTokenManager::class)->target('reports');
        $client->token(['documents.read']);
        $read = Cache::store('array')->getStore()->all();
        $client->token(['documents.write']);
        $all = Cache::store('array')->getStore()->all();
        $readKey = array_values(array_filter(array_keys($read), fn ($key) => str_starts_with($key, 'identity:service:v2:entry:')))[0] ?? '';
        self::assertNotSame('', $readKey, 'Versioned entry namespace is required');
        $writeKey = array_values(array_filter(array_diff(array_keys($all), array_keys($read)), fn ($key) => str_starts_with($key, 'identity:service:v2:entry:')))[0];
        Cache::put($writeKey, Cache::get($readKey), 300);
        self::assertSame('synthetic-new-write', $client->token(['documents.write']));
    }

    private function response(string $token, string $scope = 'documents.read'): array
    {
        return ['access_token' => $token, 'token_type' => 'Bearer', 'expires_in' => 300, 'scope' => $scope];
    }
}
