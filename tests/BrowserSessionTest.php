<?php

namespace IdentityPlatform\Laravel\Tests;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Repositories\LoginRepository;
use IdentityPlatform\Laravel\Support\SafeReturn;

class BrowserSessionTest extends TestCase
{
    public function test_login_intents_are_browser_bound_and_one_use(): void
    {
        $store = app(LoginRepository::class);
        $state = $store->create('browser-a', ['nonce' => 'private'], 'login');
        try {
            $store->consume($state, 'browser-b', 'login');
            $this->fail('Browser mismatch accepted');
        } catch (IdentityException $e) {
            $this->assertSame(401, $e->status);
        }
        $this->assertSame('private', $store->consume($state, 'browser-a', 'login')['nonce']);
        $this->expectException(IdentityException::class);
        $store->consume($state, 'browser-a', 'login');
    }

    public function test_intents_expire_and_return_paths_reject_normalization_tricks(): void
    {
        $store = app(LoginRepository::class);
        $state = $store->create('browser', [], 'login');
        $this->travel(301)->seconds();
        try {
            $store->consume($state, 'browser', 'login');
            $this->fail('Expired intent accepted');
        } catch (IdentityException $e) {
            $this->assertSame(401, $e->status);
        }
        foreach (['//evil.test', '/%2f%2fevil.test', '/a/../admin', '/%252f%252fevil', '/a\\b', '/a b', '/%0d%0aLocation:evil'] as $path) {
            $this->assertSame('/', SafeReturn::path($path));
        }
        $this->assertSame('/reports?sort=name', SafeReturn::path('/reports?sort=name'));
    }
}
