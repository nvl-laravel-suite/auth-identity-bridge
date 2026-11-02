<?php

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserSyncBinding;
use IdentityPlatform\Laravel\Sync\UserSyncManager;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\DataProvider;

class UserSyncCursorTest extends TestCase
{
    private string $cursor;

    protected function setUp(): void
    {
        parent::setUp();
        $this->configure(['identity.consumers.one.sync.enabled' => true]);
        Queue::fake();
        Http::preventStrayRequests();
        $this->cursor = 'v1.'.str_repeat('A', 350).'.'.str_repeat('B', 24);
        UserSyncBinding::create(['id' => app(IdentityConfig::class)->bindingHash(), 'policy_version' => 1, 'cycle_policy_version' => 1, 'cycle_generation' => 0, 'list_cursor' => $this->cursor]);
    }

    private function envelope(int $policy = 1): array
    {
        return ['contract' => 'platform-consumer-sync.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => $policy, 'profiles' => [], 'nextCursor' => null];
    }

    public static function invalidationCauses(): array
    {
        return ['expired' => [false], 'policy changed' => [true]];
    }

    #[DataProvider('invalidationCauses')]
    public function test_invalid_sealed_cursor_restarts_once_without_cursor_and_preserves_newer_policy(bool $changedPolicy): void
    {
        $inputs = [];
        Http::fake(function ($request) use (&$inputs, $changedPolicy) {
            $inputs[] = $request->data();
            if (count($inputs) === 1) {
                if ($changedPolicy) {
                    UserSyncBinding::query()->update(['policy_version' => 3]);
                }

                return Http::response(['error' => ['code' => 'consumer_sync_cursor_invalid', 'private' => 'private-upstream-proof']], 400);
            }

            return Http::response($this->envelope($changedPolicy ? 3 : 1));
        });
        $result = app(UserSyncManager::class)->reconcile(1);
        if ($changedPolicy) {
            $this->assertFalse($result['completed']);
            $result = app(UserSyncManager::class)->reconcile(1);
            $this->assertArrayNotHasKey('cursor', $inputs[2]);
        }
        $this->assertTrue($result['completed']);
        $this->assertCount($changedPolicy ? 3 : 2, $inputs);
        $this->assertSame($this->cursor, $inputs[0]['cursor']);
        $this->assertArrayNotHasKey('cursor', $inputs[1]);
        $this->assertNull(UserSyncBinding::firstOrFail()->list_cursor);
        $this->assertSame($changedPolicy ? 3 : 1, UserSyncBinding::firstOrFail()->policy_version);
    }

    public function test_invalid_cursor_on_restart_does_not_trigger_a_second_restart(): void
    {
        Http::fake(['*' => Http::response(['error' => ['code' => 'consumer_sync_cursor_invalid']], 400)]);
        try {
            app(UserSyncManager::class)->reconcile(1);
            $this->fail('Repeated invalid cursor accepted');
        } catch (IdentityException $error) {
            $this->assertSame('consumer_sync_cursor_invalid', $error->errorCode);
        }
        Http::assertSentCount(2);
        $this->assertNull(UserSyncBinding::firstOrFail()->list_cursor);
    }

    public function test_failed_invalid_cursor_restart_preserves_known_exhaustion_for_a_later_retry(): void
    {
        UserSyncBinding::query()->update(['known_exhausted' => true]);
        Http::fakeSequence()
            ->push(['error' => ['code' => 'consumer_sync_cursor_invalid']], 400)
            ->push([], 503)
            ->push($this->envelope());
        try {
            app(UserSyncManager::class)->reconcile(1);
            $this->fail('Failed restart accepted');
        } catch (IdentityException $error) {
            $this->assertSame(503, $error->status);
        }
        $binding = UserSyncBinding::firstOrFail();
        $this->assertNull($binding->list_cursor);
        $this->assertTrue($binding->known_exhausted);
        $this->assertFalse($binding->list_exhausted);
        $this->assertTrue(app(UserSyncManager::class)->reconcile(1)['completed']);
        $this->assertFalse($binding->refresh()->known_exhausted);
        Http::assertSentCount(3);
    }

    public static function changedProgressFlags(): array
    {
        return [
            'known changed before publish' => ['known_exhausted', false],
            'list changed before publish' => ['list_exhausted', false],
            'known changed before restart' => ['known_exhausted', true],
            'list changed before restart' => ['list_exhausted', true],
        ];
    }

    #[DataProvider('changedProgressFlags')]
    public function test_changed_exhaustion_flags_refuse_stale_publication_or_restart(string $flag, bool $restart): void
    {
        Http::fake(function () use ($flag, $restart) {
            UserSyncBinding::query()->update([$flag => true]);

            return $restart ? Http::response(['error' => ['code' => 'consumer_sync_cursor_invalid']], 400) : Http::response($this->envelope());
        });
        try {
            app(UserSyncManager::class)->reconcile(1);
            $this->fail('Changed progress overwritten');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_cursor_changed', $error->errorCode);
        }
        $this->assertTrue(UserSyncBinding::firstOrFail()->{$flag});
        $this->assertSame($this->cursor, UserSyncBinding::firstOrFail()->list_cursor);
        Http::assertSentCount(1);
    }

    public function test_lost_lease_after_known_exhaustion_cannot_publish_list_completion(): void
    {
        UserSyncBinding::query()->update(['known_exhausted' => true]);
        $key = 'identity-user-sync:'.app(IdentityConfig::class)->bindingHash();
        Http::fake(function () use ($key) {
            Cache::store('identity_tests')->lock($key, 60)->forceRelease();

            return Http::response($this->envelope());
        });
        try {
            app(UserSyncManager::class)->reconcile(1);
            $this->fail('Lost lease published completion');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_busy', $error->errorCode);
        }
        $binding = UserSyncBinding::firstOrFail();
        $this->assertTrue($binding->known_exhausted);
        $this->assertFalse($binding->list_exhausted);
        $this->assertSame($this->cursor, $binding->list_cursor);
    }

    public function test_newer_accepted_policy_refuses_stale_page_without_resetting_exhaustion(): void
    {
        UserSyncBinding::query()->update(['known_exhausted' => true]);
        Http::fake(function () {
            UserSyncBinding::query()->update(['policy_version' => 2]);

            return Http::response($this->envelope(1));
        });
        try {
            app(UserSyncManager::class)->reconcile(1);
            $this->fail('Stale policy page accepted');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_policy_stale', $error->errorCode);
        }
        $binding = UserSyncBinding::firstOrFail();
        $this->assertTrue($binding->known_exhausted);
        $this->assertFalse($binding->list_exhausted);
        $this->assertSame($this->cursor, $binding->list_cursor);
        $this->assertSame(2, $binding->policy_version);
    }

    public static function otherErrors(): array
    {
        return [[400, 'other_error', 400], [401, 'consumer_sync_cursor_invalid', 401], [403, 'consumer_sync_cursor_invalid', 403], [429, 'rate_limited', 429], [503, 'consumer_sync_cursor_invalid', 503]];
    }

    #[DataProvider('otherErrors')]
    public function test_other_errors_keep_cursor_without_restart(int $upstream, string $code, int $status): void
    {
        Http::fake(['*' => Http::response(['error' => ['code' => $code, 'private' => 'private-upstream-proof']], $upstream, ['Retry-After' => '5'])]);
        try {
            app(UserSyncManager::class)->reconcile(1);
            $this->fail('Upstream error accepted');
        } catch (IdentityException $error) {
            $this->assertSame($status, $error->status);
            $this->assertStringNotContainsString('private-upstream-proof', $error->getMessage());
            if (in_array($upstream, [429, 503], true)) {
                $this->assertSame(5, $error->retryAfter);
            }
        }
        Http::assertSentCount(1);
        $this->assertSame($this->cursor, UserSyncBinding::firstOrFail()->list_cursor);
    }
}
