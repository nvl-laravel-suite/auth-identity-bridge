<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Callbacks;

use Closure;
use IdentityPlatform\Laravel\Callbacks\CallbackReceiver;
use IdentityPlatform\Laravel\Callbacks\LogoutTokenVerifier;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Facades\Identity;
use IdentityPlatform\Laravel\Models\IdentityInbox;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;

class LogoutReceiverTest extends TestCase
{
    private string $secret;

    private array $metadata;

    private array $keys;

    private bool $keysUnavailable = false;

    protected function setUp(): void
    {
        parent::setUp();
        $pair = sodium_crypto_sign_keypair();
        $this->secret = sodium_crypto_sign_secretkey($pair);
        $this->keys = ['keys' => [[
            'kty' => 'OKP', 'kid' => 'logout-key', 'crv' => 'Ed25519', 'alg' => 'EdDSA', 'use' => 'sig',
            'x' => $this->base64url(sodium_crypto_sign_publickey($pair)),
        ]]];
        $this->metadata = ['issuer' => 'https://identity.test/api/auth', 'jwks_uri' => 'https://identity.test/api/auth/jwks'];
        Http::preventStrayRequests();
        Http::fake(function (Request $request) {
            if ($this->keysUnavailable) {
                return Http::response(['error' => 'unavailable'], 503);
            }

            return match ($request->url()) {
                'https://identity.test/api/auth/.well-known/openid-configuration' => Http::response($this->metadata),
                'https://identity.test/api/auth/jwks' => Http::response($this->keys),
                default => Http::response(['error' => 'unexpected_endpoint'], 500),
            };
        });
    }

    private function createSession(string $sid = 'sid-1', string $subject = 'user-1', ?string $binding = null): IdentitySession
    {
        return IdentitySession::query()->create([
            'id' => (string) Str::uuid(), 'binding_hash' => $binding ?? app(IdentityConfig::class)->bindingHash(),
            'user_id' => null, 'subject' => $subject, 'sid' => $sid, 'token_vault' => 'encrypted-fixture',
            'snapshot' => null, 'selection' => [], 'context_version' => 0, 'token_generation' => 0,
            'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour(),
        ]);
    }

    private function claims(array $overrides = []): array
    {
        return array_replace([
            'iss' => 'https://identity.test/api/auth', 'aud' => 'web-1', 'iat' => time() - 1, 'exp' => time() + 119,
            'jti' => 'logout-1', 'sid' => 'sid-1', 'sub' => 'user-1',
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass],
        ], $overrides);
    }

    private function token(array $claims, array $header = [], ?string $secret = null): string
    {
        $unsigned = $this->base64url(json_encode(array_replace(['alg' => 'EdDSA', 'kid' => 'logout-key', 'typ' => 'logout+jwt'], $header), JSON_THROW_ON_ERROR)).'.'.$this->base64url(json_encode($claims, JSON_THROW_ON_ERROR));

        return $unsigned.'.'.$this->base64url(sodium_crypto_sign_detached($unsigned, $secret ?? $this->secret));
    }

    private function form(string $token): string
    {
        return http_build_query(['logout_token' => $token], '', '&', PHP_QUERY_RFC3986);
    }

    private function base64url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    public function test_real_signed_logout_deletes_all_matching_local_sessions_only_and_deduplicates(): void
    {
        $first = $this->createSession();
        $second = $this->createSession();
        $differentSid = $this->createSession('sid-2');
        $differentSubject = $this->createSession(subject: 'user-2');
        $foreign = $this->createSession(binding: str_repeat('f', 64));
        $token = $this->token($this->claims());
        $receiver = app(CallbackReceiver::class);
        $this->assertSame(['duplicate' => false, 'affected' => 2], $receiver->logout($this->form($token)));
        $this->assertNull($first->fresh());
        $this->assertNull($second->fresh());
        $this->assertNotNull($differentSid->fresh());
        $this->assertNotNull($differentSubject->fresh());
        $this->assertNotNull($foreign->fresh());
        $this->assertSame(['duplicate' => true, 'affected' => 0], $receiver->logout($this->form($token)));
        $this->assertSame(hash('sha256', $token), IdentityInbox::query()->first()->body_hash);
        $this->assertSame('oidc_logout', IdentityInbox::query()->first()->protocol);
    }

    public function test_subject_only_logout_removes_all_bound_sessions_for_subject(): void
    {
        $this->createSession();
        $this->createSession('sid-2');
        $other = $this->createSession(subject: 'user-2');
        $claims = $this->claims();
        unset($claims['sid']);
        $this->assertSame(['duplicate' => false, 'affected' => 2], app(CallbackReceiver::class)->logout($this->form($this->token($claims))));
        $this->assertNotNull($other->fresh());
    }

    public function test_sid_only_token_and_unknown_sid_are_valid_and_exp_is_optional(): void
    {
        $claims = $this->claims(['sid' => 'unknown']);
        unset($claims['sub'], $claims['exp']);
        $this->assertSame(['duplicate' => false, 'affected' => 0], app(CallbackReceiver::class)->logout($this->form($this->token($claims))));
    }

    public function test_supported_future_iat_tolerance_is_thirty_seconds_without_exp_or_nbf_leeway(): void
    {
        $token = $this->token($this->claims(['iat' => time() + 25, 'exp' => time() + 60]));
        $this->assertSame(['duplicate' => false, 'affected' => 0], app(CallbackReceiver::class)->logout($this->form($token)));
    }

    public static function invalidClaims(): array
    {
        return [
            'foreign issuer' => [['iss' => 'https://evil.test/api/auth']],
            'foreign audience' => [['aud' => 'web-other']],
            'nonce forbidden even null' => [['nonce' => null]],
            'bad event value array' => [['events' => ['http://schemas.openid.net/event/backchannel-logout' => []]]],
            'wrong event' => [['events' => ['user.deleted' => new \stdClass]]],
            'extra event' => [['events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass, 'other' => new \stdClass]]],
            'empty sid' => [['sid' => '']],
            'control sub' => [['sub' => "bad\nsubject"]],
            'string iat' => [['iat' => '100']],
            'missing scope' => [['sid' => null, 'sub' => null]],
            'old iat' => [['iat' => time() - 301]],
            'future iat' => [static fn (): array => ['iat' => time() + 60]],
            'expired exp' => [['exp' => time() - 1]],
            'string exp' => [['exp' => (string) (time() + 60)]],
            'future nbf' => [static fn (): array => ['nbf' => time() + 60]],
            'empty jti' => [['jti' => '']],
        ];
    }

    #[DataProvider('invalidClaims')]
    public function test_invalid_signed_claims_cannot_create_receipt_or_delete_session(array|Closure $overrides): void
    {
        $session = $this->createSession();
        $overrides = $overrides instanceof Closure ? $overrides() : $overrides;
        try {
            app(CallbackReceiver::class)->logout($this->form($this->token($this->claims($overrides))));
            $this->fail('Invalid signed Logout Token accepted');
        } catch (IdentityException $error) {
            $this->assertSame('logout_token_invalid', $error->errorCode);
            $this->assertSame(400, $error->status);
            $this->assertSame(0, IdentityInbox::query()->count());
            $this->assertNotNull($session->fresh());
        }
    }

    public function test_forged_signature_and_id_token_typ_never_pass_logout_verification(): void
    {
        $otherSecret = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
        foreach ([$this->token($this->claims(), secret: $otherSecret), $this->token($this->claims(), ['typ' => 'JWT']), $this->token($this->claims(), ['alg' => 'HS256']), $this->token($this->claims(), ['b64' => false])] as $token) {
            try {
                app(CallbackReceiver::class)->logout($this->form($token));
                $this->fail('Forged Logout Token accepted');
            } catch (IdentityException $error) {
                $this->assertSame('logout_token_invalid', $error->errorCode);
            }
        }
        $this->assertSame(0, IdentityInbox::query()->count());
    }

    public function test_form_duplicate_fields_unknown_fields_and_invalid_utf8_are_refused(): void
    {
        $form = $this->form($this->token($this->claims()));
        foreach ([$form.'&'.$form, $form.'&extra=1', $form.'&logout_token%5B%5D=second', "logout_token=\xff"] as $raw) {
            try {
                app(CallbackReceiver::class)->logout($raw);
                $this->fail('Ambiguous form accepted');
            } catch (IdentityException $error) {
                $this->assertSame('logout_token_invalid', $error->errorCode);
            }
        }
    }

    public function test_token_selected_jwks_cannot_override_trusted_discovery_and_foreign_metadata_is_refused(): void
    {
        $token = $this->token($this->claims(), ['jku' => 'https://evil.test/jwks']);
        $this->assertSame(['duplicate' => false, 'affected' => 0], app(CallbackReceiver::class)->logout($this->form($token)));
        $this->metadata['jwks_uri'] = 'https://evil.test/jwks';
        $this->travel(301)->seconds();
        try {
            app(CallbackReceiver::class)->logout($this->form($this->token($this->claims(['jti' => 'logout-2']))));
            $this->fail('Foreign metadata accepted');
        } catch (IdentityException $error) {
            $this->assertSame('logout_keys_unavailable', $error->errorCode);
            Http::assertNotSent(fn (Request $request) => str_starts_with($request->url(), 'https://evil.test'));
        }
    }

    public function test_trusted_discovery_and_keys_are_shared_across_verifiers_until_the_cache_expires(): void
    {
        app(LogoutTokenVerifier::class)->verify($this->token($this->claims()));
        app(LogoutTokenVerifier::class)->verify($this->token($this->claims(['jti' => 'another'])));
        Http::assertSentCount(2);
        $this->travel(301)->seconds();
        app(LogoutTokenVerifier::class)->verify($this->token($this->claims(['iat' => now()->timestamp, 'exp' => now()->timestamp + 100])));
        Http::assertSentCount(4);
    }

    public function test_unknown_key_refresh_is_bounded_across_different_attacker_key_ids(): void
    {
        $verifier = app(LogoutTokenVerifier::class);
        $verifier->verify($this->token($this->claims()));
        for ($i = 0; $i < 5; $i++) {
            try {
                $verifier->verify($this->token($this->claims(), ['kid' => 'unknown-'.$i]));
                $this->fail('Unknown signing key accepted');
            } catch (IdentityException $error) {
                $this->assertSame('logout_token_invalid', $error->errorCode);
            }
        }
        Http::assertSentCount(3);
        $this->travel(31)->seconds();
        try {
            $verifier->verify($this->token($this->claims(), ['kid' => 'still-unknown']));
            $this->fail('Unknown signing key accepted after refresh cooldown');
        } catch (IdentityException $error) {
            $this->assertSame('logout_token_invalid', $error->errorCode);
        }
        Http::assertSentCount(4);
    }

    public function test_expired_cached_keys_cannot_verify_logout_during_an_upstream_outage(): void
    {
        $verifier = app(LogoutTokenVerifier::class);
        $verifier->verify($this->token($this->claims()));
        $this->keysUnavailable = true;
        $this->travel(301)->seconds();
        $this->expectExceptionObject(new IdentityException('logout_keys_unavailable', 503));
        $verifier->verify($this->token($this->claims(['iat' => now()->timestamp, 'exp' => now()->timestamp + 100])));
    }

    public function test_remote_key_rotation_is_resolved_from_current_trusted_jwks(): void
    {
        $receiver = app(CallbackReceiver::class);
        $receiver->logout($this->form($this->token($this->claims())));
        $pair = sodium_crypto_sign_keypair();
        $this->secret = sodium_crypto_sign_secretkey($pair);
        $this->keys['keys'][0]['kid'] = 'rotated-key';
        $this->keys['keys'][0]['x'] = $this->base64url(sodium_crypto_sign_publickey($pair));
        $token = $this->token($this->claims(['jti' => 'logout-rotated']), ['kid' => 'rotated-key']);
        $this->assertSame(['duplicate' => false, 'affected' => 0], $receiver->logout($this->form($token)));
        $this->assertSame(2, IdentityInbox::query()->count());
    }

    public function test_same_message_id_is_independent_between_signed_event_and_logout_protocols(): void
    {
        $receiver = app(CallbackReceiver::class);
        $body = json_encode(['schema_version' => 1, 'event_id' => 'logout-1', 'type' => 'service.updated', 'application_id' => 'app-1', 'occurred_at' => '2026-10-28T12:00:00Z', 'subject' => null], JSON_THROW_ON_ERROR);
        $timestamp = (string) time();
        $receiver->event($body, ['x-identity-event-id' => 'logout-1', 'x-identity-timestamp' => $timestamp, 'x-identity-signature' => 'v1='.hash_hmac('sha256', 'logout-1.'.$timestamp.'.'.$body, str_repeat('e', 32))]);
        $token = $this->token($this->claims());
        $this->assertSame(['duplicate' => false, 'affected' => 0], $receiver->logout($this->form($token)));
        $this->assertSame(2, IdentityInbox::query()->count());
        $this->assertStringNotContainsString($token, IdentityInbox::query()->get()->toJson());
    }

    public function test_key_fetch_outage_does_not_consume_message_or_delete_sessions(): void
    {
        $session = $this->createSession();
        $this->keysUnavailable = true;
        try {
            app(CallbackReceiver::class)->logout($this->form($this->token($this->claims())));
            $this->fail('Unavailable trusted keys accepted');
        } catch (IdentityException $error) {
            $this->assertSame('logout_keys_unavailable', $error->errorCode);
            $this->assertSame(503, $error->status);
            $this->assertSame(0, IdentityInbox::query()->count());
            $this->assertNotNull($session->fresh());
        }
    }

    public function test_jti_reuse_with_different_signed_token_is_a_conflict(): void
    {
        $receiver = app(CallbackReceiver::class);
        $receiver->logout($this->form($this->token($this->claims())));
        $this->expectExceptionObject(new IdentityException('callback_replay_conflict', 409));
        $receiver->logout($this->form($this->token($this->claims(['sid' => 'other']))));
    }

    public function test_receipt_rolls_back_when_local_session_deletion_fails(): void
    {
        $session = $this->createSession();
        DB::listen(function (QueryExecuted $query): void {
            if (str_starts_with($query->sql, 'delete from "identity_sessions"')) {
                throw new CallbackDatabaseFailure('fixture-database-failure');
            }
        });
        try {
            app(CallbackReceiver::class)->logout($this->form($this->token($this->claims())));
            $this->fail('Database failure accepted');
        } catch (IdentityException|CallbackDatabaseFailure) {
            $this->assertSame(0, IdentityInbox::query()->count());
            $this->assertNotNull($session->fresh());
        }
    }

    public function test_two_named_clients_retain_exact_logout_audience_and_binding(): void
    {
        $second = config('identity.consumers.one');
        $second['app_origin'] = 'https://second.test';
        $second['browser']['client_id'] = 'web-2';
        $second['browser']['redirect_uri'] = 'https://second.test/auth/callback';
        $second['browser']['post_logout_redirect_uri'] = 'https://second.test/signed-out';
        $second['routes']['event_uri'] = 'https://second.test/events';
        $second['routes']['backchannel_logout_uri'] = 'https://second.test/logout';
        $second['routes']['guard'] = 'identity_two';
        $this->configure(['identity.consumers.two' => $second]);
        $one = Identity::consumer('one');
        $two = Identity::consumer('two');
        $first = $this->createSession(binding: $one->context->bindingHash());
        $secondSession = $this->createSession(binding: $two->context->bindingHash());
        $firstToken = $this->form($this->token($this->claims()));
        try {
            $two->make(CallbackReceiver::class)->logout($firstToken);
            $this->fail('Cross-client audience accepted');
        } catch (IdentityException $error) {
            $this->assertSame('logout_token_invalid', $error->errorCode);
            $this->assertSame(400, $error->status);
        }
        $this->assertNotNull($first->fresh());
        $this->assertNotNull($secondSession->fresh());
        $this->assertSame(1, $one->make(CallbackReceiver::class)->logout($firstToken)['affected']);
        $this->assertNotNull($secondSession->fresh());
        $this->assertSame(1, $two->make(CallbackReceiver::class)->logout($this->form($this->token($this->claims(['aud' => 'web-2']))))['affected']);
        $this->assertSame(2, IdentityInbox::query()->count());
    }
}
