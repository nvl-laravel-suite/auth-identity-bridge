<?php

namespace IdentityPlatform\Laravel\Tests\Consumer;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Http;

class ConsumerTransportTest extends TestCase
{
    public function test_known_proof_error_and_bounded_retry_are_available_without_upstream_body(): void
    {
        Http::fake(['*' => Http::response(['error' => ['code' => 'mfa_required', 'private' => 'never-expose-this']], 403, ['Retry-After' => '60'])]);
        try {
            app(IdentityHttp::class)->json('/api/consumer/v1/self/profile', []);
            self::fail('Upstream rejection was accepted');
        } catch (IdentityException $error) {
            self::assertSame('mfa_required', $error->errorCode);
            self::assertSame(60, $error->retryAfter);
            self::assertStringNotContainsString('never-expose-this', $error->getMessage());
        }
    }

    public function test_unknown_error_text_and_unbounded_retry_are_not_propagated(): void
    {
        Http::fake(['*' => Http::response(['error' => ['code' => 'secret-token-value']], 502, ['Retry-After' => '9999999'])]);
        try {
            app(IdentityHttp::class)->json('/api/consumer/v1/self/read', []);
            self::fail('Upstream rejection was accepted');
        } catch (IdentityException $error) {
            self::assertSame('upstream_rejected', $error->errorCode);
            self::assertSame(503, $error->status);
            self::assertNull($error->retryAfter);
        }
    }
}
