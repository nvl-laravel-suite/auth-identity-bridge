<?php

namespace IdentityPlatform\Laravel\Tests;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Support\IdentityVault;
use Illuminate\Support\Facades\Http;

class FoundationTest extends TestCase
{
    public function test_transport_refuses_foreign_origin_and_redirects_without_leaking_body(): void
    {
        Http::fake(['*' => Http::response('secret-token', 302, ['Location' => 'https://evil.test'])]);
        $http = app(IdentityHttp::class);
        foreach (['https://evil.test/jwks', '/api/auth/jwks'] as $url) {
            try {
                $http->get($url);
                $this->fail('Unsafe request accepted');
            } catch (IdentityException $e) {
                $this->assertStringNotContainsString('secret-token', $e->getMessage());
            }
        }
        Http::assertSentCount(1);
    }

    public function test_vault_is_bound_to_purpose_and_configuration(): void
    {
        $vault = app(IdentityVault::class);
        $sealed = $vault->seal(['access_token' => 'private'], 'session-a');
        $this->assertSame('private', $vault->open($sealed, 'session-a')['access_token']);
        $this->expectException(IdentityException::class);
        $vault->open($sealed, 'session-b');
    }

    public function test_binding_changes_when_consumer_or_browser_client_changes(): void
    {
        $config = app(IdentityConfig::class);
        $before = $config->bindingHash();
        $this->configure(['identity.consumers.one.browser.client_id' => 'other']);
        $this->assertSame($before, $config->bindingHash());
        $this->assertNotSame($before, app(IdentityConfig::class)->bindingHash());
    }
}
