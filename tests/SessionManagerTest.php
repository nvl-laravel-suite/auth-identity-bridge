<?php

namespace IdentityPlatform\Laravel\Tests;

use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;

class SessionManagerTest extends TestCase
{
    private function browser(): Request
    {
        $request = Request::create('https://consumer.test/');
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        $store->put('identity.session', 'local-session');
        $request->setLaravelSession($store);

        return $request;
    }

    private function row(array $overrides = []): IdentitySession
    {
        return IdentitySession::create(array_replace(['id' => 'local-session', 'binding_hash' => app(IdentityConfig::class)->bindingHash(), 'user_id' => null, 'subject' => 'person', 'sid' => 'central', 'token_vault' => app(IdentityVault::class)->seal(['access_token' => 'private', 'expires_at' => time() + 300], 'session:local-session'), 'selection' => [], 'context_version' => 1, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHours(12)], $overrides));
    }

    public function test_current_session_uses_opaque_framework_reference_and_independent_deadlines(): void
    {
        $this->row();
        $request = $this->browser();
        $this->assertSame('person', app(SessionManager::class)->current($request)->subject);
        $this->assertSame('local-session', $request->session()->get('identity.session'));
        $this->assertStringNotContainsString('private', json_encode($request->session()->all()));
        $this->travel(1801)->seconds();
        $this->assertNull(app(SessionManager::class)->current($request));
        $this->assertDatabaseCount('identity_sessions', 0);
    }

    public function test_missing_session_clears_the_stale_browser_pointer(): void
    {
        $request = $this->browser();
        $this->assertNull(app(SessionManager::class)->current($request));
        $this->assertNull($request->session()->get('identity.session'));
    }

    public function test_refresh_waiter_advances_activity_for_the_already_renewed_session(): void
    {
        $vault = app(IdentityVault::class);
        $this->row(['last_activity_at' => now()->subMinutes(10), 'token_vault' => $vault->seal(['expires_at' => time() - 1], 'session:local-session')]);
        $pending = true;
        DB::listen(function ($query) use (&$pending, $vault): void {
            if ($pending && str_starts_with($query->sql, 'select') && str_contains($query->sql, 'identity_sessions')) {
                $pending = false;
                IdentitySession::whereKey('local-session')->update(['token_vault' => $vault->seal(['expires_at' => time() + 300], 'session:local-session'), 'token_generation' => 2]);
            }
        });
        $request = $this->browser();
        $current = app(SessionManager::class)->current($request);
        $this->assertSame(2, $current->token_generation);
        $this->assertEquals(now()->startOfSecond(), $current->fresh()->last_activity_at);
    }

    public function test_refresh_waiter_clears_pointer_when_the_locked_session_has_expired(): void
    {
        $this->row(['token_vault' => app(IdentityVault::class)->seal(['expires_at' => time() - 1], 'session:local-session')]);
        $pending = true;
        DB::listen(function ($query) use (&$pending): void {
            if ($pending && str_starts_with($query->sql, 'select') && str_contains($query->sql, 'identity_sessions')) {
                $pending = false;
                IdentitySession::whereKey('local-session')->update(['expires_at' => now()->subSecond()]);
            }
        });
        $request = $this->browser();
        $this->assertNull(app(SessionManager::class)->current($request));
        $this->assertNull($request->session()->get('identity.session'));
        $this->assertDatabaseCount('identity_sessions', 0);
    }

    public function test_absolute_start_cannot_be_extended_by_last_activity_or_new_expiry(): void
    {
        $this->row(['started_at' => now()->subHours(13), 'last_activity_at' => now(), 'expires_at' => now()->addDay()]);
        $this->assertNull(app(SessionManager::class)->current($this->browser()));
    }

    public function test_unselected_or_expired_authority_is_not_used_from_cache(): void
    {
        $this->row(['snapshot' => ['permissions' => ['everything'], 'expires_at' => now()->subSecond()->toIso8601String()]]);
        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('context_required');
        app(SessionManager::class)->principal($this->browser());
    }
}
