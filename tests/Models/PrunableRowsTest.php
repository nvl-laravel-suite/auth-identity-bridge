<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Models;

use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityInbox;
use IdentityPlatform\Laravel\Models\IdentityLogin;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\LoginRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\DB;

/** The host's standard model:prune schedule removes only rows that verification already refuses. */
final class PrunableRowsTest extends TestCase
{
    public function test_expired_login_transactions_are_pruned_and_a_pending_one_stays_redeemable(): void
    {
        $logins = app(LoginRepository::class);
        $abandoned = $logins->create('abandoned-browser', ['nonce' => 'abandoned'], 'login');
        $pending = $logins->create('pending-browser', ['nonce' => 'pending'], 'login');
        DB::table('identity_logins')->where('id', hash('sha256', $abandoned))->update(['expires_at' => now()->subSecond()]);

        $this->prune(IdentityLogin::class);

        self::assertSame([hash('sha256', $pending)], IdentityLogin::query()->pluck('id')->all());
        self::assertSame('pending', $logins->consume($pending, 'pending-browser', 'login')['nonce']);
        $this->expectExceptionObject(new IdentityException('invalid_login_state', 401));
        $logins->consume($abandoned, 'abandoned-browser', 'login');
    }

    public function test_sessions_past_their_absolute_deadline_are_pruned_and_live_or_idle_ones_are_kept(): void
    {
        $this->storeSession('expired', ['started_at' => now()->subHours(13), 'last_activity_at' => now()->subHours(12), 'expires_at' => now()->subSecond()]);
        $this->storeSession('live', ['started_at' => now()->subHour(), 'last_activity_at' => now(), 'expires_at' => now()->addHours(11)]);
        // Idle expiry depends on each consumer's configuration; such a row waits for its absolute deadline.
        $this->storeSession('idle', ['started_at' => now()->subHours(2), 'last_activity_at' => now()->subHours(2), 'expires_at' => now()->addHours(10)]);
        $manager = app(SessionManager::class);
        self::assertFalse($manager->live(IdentitySession::query()->findOrFail('expired')));
        self::assertTrue($manager->live(IdentitySession::query()->findOrFail('live')));

        $this->prune(IdentitySession::class);

        self::assertSame(['idle', 'live'], IdentitySession::query()->orderBy('id')->pluck('id')->all());
    }

    public function test_receipts_older_than_every_replay_window_are_pruned_and_recent_ones_are_kept(): void
    {
        $this->storeReceipt('old', now()->subSeconds(IdentityInbox::RETENTION_SECONDS + 1));
        $this->storeReceipt('replayable', now()->subSeconds(600));
        $this->storeReceipt('fresh', now());

        $this->prune(IdentityInbox::class);

        self::assertSame(['fresh', 'replayable'], IdentityInbox::query()->orderBy('id')->pluck('id')->all());
    }

    /** @param class-string $model */
    private function prune(string $model): void
    {
        $this->artisan('model:prune', ['--model' => [$model]])->assertSuccessful();
    }

    /** @param array<string, mixed> $deadlines */
    private function storeSession(string $id, array $deadlines): void
    {
        IdentitySession::query()->create(['id' => $id, 'binding_hash' => app(IdentityConfig::class)->bindingHash(), 'user_id' => null, 'subject' => 'subject-'.$id, 'sid' => 'sid-'.$id,
            'token_vault' => 'encrypted-fixture', 'selection' => [], 'snapshot' => null, 'context_version' => 1, 'token_generation' => 1, ...$deadlines]);
    }

    private function storeReceipt(string $id, \DateTimeInterface $receivedAt): void
    {
        IdentityInbox::query()->create(['id' => $id, 'binding_hash' => app(IdentityConfig::class)->bindingHash(), 'protocol' => 'identity_event', 'message_id' => 'event-'.$id, 'body_hash' => hash('sha256', $id), 'received_at' => $receivedAt]);
    }
}
