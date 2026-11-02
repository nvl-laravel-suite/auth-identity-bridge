<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Callbacks;

use IdentityPlatform\Laravel\Callbacks\CallbackReceiver;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityInbox;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;

class CallbackReceiverTest extends TestCase
{
    public function test_rotation_accepts_both_keys_once_and_rejects_the_old_key_at_its_deadline(): void
    {
        $this->createSession();
        $body = $this->envelope();
        $oldHeaders = $this->headers($body);
        $this->configure(['identity.consumers.one.callbacks.event_secret' => str_repeat('n', 32),
            'identity.consumers.one.callbacks.event_secret_previous' => str_repeat('e', 32),
            'identity.consumers.one.callbacks.event_secret_previous_expires_at' => now()->addMinute()->format('Y-m-d\TH:i:s\Z')]);
        $receiver = app(CallbackReceiver::class);
        $this->assertSame(['duplicate' => false, 'affected' => 1], $receiver->event($body, $oldHeaders));
        $newHeaders = $oldHeaders;
        $newHeaders['X-Identity-Signature'] = ['v1='.hash_hmac('sha256', 'event-1.'.$oldHeaders['X-Identity-Timestamp'][0].'.'.$body, str_repeat('n', 32))];
        $this->assertSame(['duplicate' => true, 'affected' => 0], $receiver->event($body, $newHeaders));
        $this->assertSame(1, IdentityInbox::query()->count());
        $this->travel(60)->seconds();
        $this->expectExceptionMessage('event_signature_invalid');
        $receiver->event($body, $oldHeaders);
    }

    public function test_a_previous_key_requires_an_explicit_valid_deadline(): void
    {
        $this->expectExceptionMessage('invalid_identity_configuration');
        $this->configure(['identity.consumers.one.callbacks.event_secret_previous' => str_repeat('p', 32)]);
        $body = $this->envelope();
        $this->expectExceptionMessage('event_receiver_configuration_invalid');
        app(CallbackReceiver::class)->event($body, $this->headers($body));
    }

    private function createSession(string $subject = 'user-1', string $sid = 'sid-1', ?string $binding = null): IdentitySession
    {
        return IdentitySession::query()->create([
            'id' => (string) Str::uuid(), 'binding_hash' => $binding ?? app(IdentityConfig::class)->bindingHash(),
            'user_id' => null, 'subject' => $subject, 'sid' => $sid, 'token_vault' => 'encrypted-fixture',
            'selection' => [], 'snapshot' => ['permissions' => ['document.read']], 'context_version' => 4,
            'token_generation' => 0, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour(),
        ]);
    }

    private function envelope(array $overrides = []): string
    {
        return json_encode(array_replace([
            'schema_version' => 1, 'event_id' => 'event-1', 'type' => 'grant.revoked',
            'application_id' => 'app-1', 'occurred_at' => '2026-10-28T12:00:00.000Z', 'subject' => 'user-1',
        ], $overrides), JSON_THROW_ON_ERROR);
    }

    private function headers(string $body, string $eventId = 'event-1', ?int $timestamp = null): array
    {
        $timestamp ??= time();

        return [
            'X-Identity-Event-Id' => [$eventId], 'X-Identity-Timestamp' => [(string) $timestamp],
            'X-Identity-Signature' => ['v1='.hash_hmac('sha256', $eventId.'.'.$timestamp.'.'.$body, str_repeat('e', 32))],
        ];
    }

    public function test_signed_grant_invalidates_only_bound_subject_and_duplicate_has_no_second_effect(): void
    {
        $selected = $this->createSession();
        $other = $this->createSession('user-2');
        $foreign = $this->createSession(binding: str_repeat('f', 64));
        $body = $this->envelope();
        $receiver = app(CallbackReceiver::class);
        $this->assertSame(['duplicate' => false, 'affected' => 1], $receiver->event($body, $this->headers($body)));
        $this->assertNull($selected->fresh()->snapshot);
        $this->assertSame(5, $selected->fresh()->context_version);
        $this->assertNotNull($other->fresh()->snapshot);
        $this->assertNotNull($foreign->fresh()->snapshot);
        $this->assertSame(['duplicate' => true, 'affected' => 0], $receiver->event($body, $this->headers($body)));
        $this->assertSame(5, $selected->fresh()->context_version);
        $this->assertSame(1, IdentityInbox::query()->count());
        $this->assertSame(hash('sha256', $body), IdentityInbox::query()->first()->body_hash);
    }

    public function test_application_invalidation_fences_all_bound_sessions_but_never_deletes_them(): void
    {
        $first = $this->createSession();
        $second = $this->createSession('user-2');
        $foreign = $this->createSession(binding: str_repeat('f', 64));
        $body = $this->envelope(['type' => 'catalog.published', 'subject' => null]);
        $this->assertSame(['duplicate' => false, 'affected' => 2], app(CallbackReceiver::class)->event($body, $this->headers($body)));
        $this->assertNull($first->fresh()->snapshot);
        $this->assertNull($second->fresh()->snapshot);
        $this->assertNotNull($foreign->fresh()->snapshot);
        $this->assertSame(3, IdentitySession::query()->count());
    }

    public function test_non_invalidating_event_is_receipted_without_session_changes(): void
    {
        $session = $this->createSession();
        $body = $this->envelope(['type' => 'service.updated']);
        $this->assertSame(['duplicate' => false, 'affected' => 0], app(CallbackReceiver::class)->event($body, $this->headers($body)));
        $this->assertSame(4, $session->fresh()->context_version);
    }

    public function test_profile_event_invalidates_only_bound_subject_without_writing_profile_data(): void
    {
        $profile = app(UserSynchronizer::class)->sync(['sub' => 'user-1', 'name' => 'Verified original']);
        $selected = $this->createSession();
        $other = $this->createSession('user-2');
        $foreign = $this->createSession(binding: str_repeat('f', 64));
        $body = $this->envelope(['type' => 'profile.invalidated']);
        $this->assertSame(['duplicate' => false, 'affected' => 1], app(CallbackReceiver::class)->event($body, $this->headers($body)));
        $this->assertNull($selected->refresh()->snapshot);
        $this->assertSame(5, $selected->context_version);
        $this->assertSame(4, $other->refresh()->context_version);
        $this->assertSame(4, $foreign->refresh()->context_version);
        $this->assertSame('Verified original', $profile->refresh()->name);
        $this->assertSame(1, IdentityUser::query()->count());
    }

    public function test_same_event_id_with_changed_authenticated_bytes_conflicts(): void
    {
        $receiver = app(CallbackReceiver::class);
        $body = $this->envelope();
        $receiver->event($body, $this->headers($body));
        $changed = $this->envelope(['subject' => 'user-2']);
        try {
            $receiver->event($changed, $this->headers($changed));
            $this->fail('Changed event replay accepted');
        } catch (IdentityException $error) {
            $this->assertSame('callback_replay_conflict', $error->errorCode);
            $this->assertSame(409, $error->status);
            $this->assertSame(1, IdentityInbox::query()->count());
        }
    }

    public static function invalidEvents(): array
    {
        return [
            'wrong app' => [['application_id' => 'app-other'], 'event_application_mismatch'],
            'wrong schema' => [['schema_version' => 2], 'event_payload_invalid'],
            'invented sync' => [['type' => 'user.updated'], 'event_payload_invalid'],
            'metadata is private' => [['metadata' => ['email' => 'private@example.test']], 'event_payload_invalid'],
            'missing grant subject' => [['subject' => null], 'event_subject_required'],
            'missing profile subject' => [['type' => 'profile.invalidated', 'subject' => null], 'event_subject_required'],
            'profile patch is private' => [['type' => 'profile.invalidated', 'profile' => ['name' => 'Forged']], 'event_payload_invalid'],
            'invalid calendar' => [['occurred_at' => '2026-02-30T12:00:00Z'], 'event_payload_invalid'],
        ];
    }

    #[DataProvider('invalidEvents')]
    public function test_authenticated_invalid_envelopes_cannot_create_receipts(array $overrides, string $code): void
    {
        $body = $this->envelope($overrides);
        try {
            app(CallbackReceiver::class)->event($body, $this->headers($body));
            $this->fail('Invalid event accepted');
        } catch (IdentityException $error) {
            $this->assertSame($code, $error->errorCode);
            $this->assertSame(0, IdentityInbox::query()->count());
        }
    }

    public function test_raw_bytes_freshness_header_binding_and_size_are_authenticated_before_receipts(): void
    {
        $body = $this->envelope();
        $badSignature = $this->headers($body);
        $badSignature['X-Identity-Signature'] = ['v1='.str_repeat('0', 64)];
        $duplicateHeader = $this->headers($body);
        $duplicateHeader['X-Identity-Event-Id'][] = 'event-other';
        foreach ([[$body.' ', $this->headers($body)], [$body, $badSignature], [$body, $duplicateHeader], [$body, $this->headers($body, timestamp: time() - 301)], [str_repeat('x', 65537), $this->headers(str_repeat('x', 65537))]] as [$raw, $headers]) {
            try {
                app(CallbackReceiver::class)->event($raw, $headers);
                $this->fail('Unauthenticated body accepted');
            } catch (IdentityException $error) {
                $this->assertContains($error->errorCode, ['event_signature_invalid', 'callback_body_limit']);
            }
        }
        $this->assertSame(0, IdentityInbox::query()->count());
    }

    public function test_signed_header_event_id_must_equal_payload_event_id(): void
    {
        $body = $this->envelope();
        $this->expectExceptionObject(new IdentityException('event_id_mismatch', 400));
        app(CallbackReceiver::class)->event($body, $this->headers($body, 'event-other'));
    }

    public function test_missing_secret_disables_generic_receiver(): void
    {
        $this->configure(['identity.consumers.one.callbacks.event_secret' => null]);
        $this->expectExceptionObject(new IdentityException('event_receiver_disabled', 404));
        app(CallbackReceiver::class)->event($this->envelope(), []);
    }

    public function test_same_event_has_independent_receipts_for_consumer_origin_namespaces(): void
    {
        $first = $this->createSession();
        $body = $this->envelope();
        $receiver = app(CallbackReceiver::class);
        $receiver->event($body, $this->headers($body));
        $this->configure(['identity.consumers.one.app_origin' => 'https://other-consumer.test',
            'identity.consumers.one.browser.redirect_uri' => 'https://other-consumer.test/auth/callback',
            'identity.consumers.one.browser.post_logout_redirect_uri' => 'https://other-consumer.test/signed-out',
            'identity.consumers.one.routes.event_uri' => 'https://other-consumer.test/identity/events',
            'identity.consumers.one.routes.backchannel_logout_uri' => 'https://other-consumer.test/auth/backchannel-logout']);
        $receiver = app(CallbackReceiver::class);
        $second = $this->createSession();
        $this->assertSame(['duplicate' => false, 'affected' => 1], $receiver->event($body, $this->headers($body)));
        $this->assertSame(5, $first->fresh()->context_version);
        $this->assertSame(5, $second->fresh()->context_version);
        $this->assertSame(2, IdentityInbox::query()->count());
    }

    public function test_inbox_insert_rolls_back_when_session_invalidation_fails(): void
    {
        $session = $this->createSession();
        DB::listen(function (QueryExecuted $query): void {
            if (str_starts_with($query->sql, 'update "identity_sessions"')) {
                throw new CallbackDatabaseFailure('fixture-database-failure');
            }
        });
        $body = $this->envelope();
        try {
            app(CallbackReceiver::class)->event($body, $this->headers($body));
            $this->fail('Database failure accepted');
        } catch (IdentityException|CallbackDatabaseFailure) {
            $this->assertSame(0, IdentityInbox::query()->count());
            $this->assertSame(4, $session->fresh()->context_version);
        }
    }
}
