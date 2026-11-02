<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Http;

use IdentityPlatform\Laravel\Http\Controllers\CallbackController;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Tests\Callbacks\CallbackDatabaseFailure;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;

class BrowserPipelineTest extends TestCase
{
    public function test_invalid_callback_renders_sanitized_expected_status_through_actual_routing_pipeline(): void
    {
        $this->configure(['app.debug' => true]);
        $response = $this->get('https://consumer.test/auth/callback?state='.str_repeat('a', 64).'&code=private-code');
        $response->assertStatus(401)->assertExactJson(['error' => 'invalid_login_state']);
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        $this->assertStringNotContainsString('private-code', $response->getContent());
        $this->assertStringNotContainsString('trace', $response->getContent());
    }

    public function test_permission_denial_is_a_safe_native_status_when_identity_safety_is_not_on_host_route(): void
    {
        Route::middleware(['web', 'identity.permission:documents.read'])->get('/package-protected', fn () => response('unsafe'));
        $response = $this->getJson('https://consumer.test/package-protected');
        $response->assertStatus(401)->assertExactJson(['error' => 'sign_in_required']);
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
    }

    public function test_duplicate_encoded_oauth_response_parameters_are_refused_before_login_state_consumption(): void
    {
        $this->getJson('https://consumer.test/auth/callback?state='.str_repeat('a', 64).'&%73tate='.str_repeat('b', 64).'&code=private-code')
            ->assertStatus(400)->assertExactJson(['error' => 'callback_invalid']);
    }

    public function test_request_guard_drops_cached_user_when_a_worker_rebinds_the_next_request(): void
    {
        $this->configure(['auth.guards.identity' => ['driver' => 'identity'], 'auth.defaults.guard' => 'identity']);
        $user = IdentityUser::query()->create(['identity_key' => hash('sha256', 'fixture'), 'issuer' => 'https://identity.test/api/auth', 'subject' => 'person']);
        $id = 'local-session';
        IdentitySession::query()->create([
            'id' => $id, 'binding_hash' => app(IdentityConfig::class)->bindingHash(), 'user_id' => $user->id,
            'subject' => 'person', 'sid' => 'central', 'token_vault' => app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:'.$id),
            'selection' => [], 'context_version' => 1, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour(),
        ]);
        $first = $this->requestWithSession($id);
        $this->bindRequest($first);
        $guard = Auth::guard('identity');
        $this->assertSame($user->id, $guard->user()->id);
        $second = $this->requestWithSession();
        $this->bindRequest($second);
        $this->assertNull($guard->user());
    }

    public function test_callback_controller_preserves_duplicate_signature_header_evidence(): void
    {
        $body = $this->eventBody();
        $timestamp = (string) time();
        $request = Request::create('https://consumer.test/identity/events', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], $body);
        $request->headers->set('x-identity-event-id', ['event-1', 'event-other']);
        $request->headers->set('x-identity-timestamp', $timestamp);
        $request->headers->set('x-identity-signature', 'v1='.hash_hmac('sha256', 'event-1.'.$timestamp.'.'.$body, str_repeat('e', 32)));
        $response = app(CallbackController::class)->event($request);
        $this->assertSame(401, $response->getStatusCode());
    }

    public function test_callback_database_outage_is_sanitized_retryable_and_rolls_back_receipt(): void
    {
        DB::listen(function (QueryExecuted $query): void {
            if (str_starts_with($query->sql, 'insert into "identity_inbox"')) {
                throw new CallbackDatabaseFailure('fixture-database-failure');
            }
        });
        $body = $this->eventBody();
        $timestamp = (string) time();
        $response = $this->call('POST', 'https://consumer.test/identity/events', [], [], [], [
            'CONTENT_TYPE' => 'application/json', 'HTTP_X_IDENTITY_EVENT_ID' => 'event-1',
            'HTTP_X_IDENTITY_TIMESTAMP' => $timestamp,
            'HTTP_X_IDENTITY_SIGNATURE' => 'v1='.hash_hmac('sha256', 'event-1.'.$timestamp.'.'.$body, str_repeat('e', 32)),
        ], $body);
        $response->assertStatus(503)->assertExactJson(['error' => 'callback_unavailable']);
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        $this->assertStringNotContainsString('fixture-database-failure', $response->getContent());
        $this->assertDatabaseCount('identity_inbox', 0);
    }

    private function eventBody(): string
    {
        return json_encode(['schema_version' => 1, 'event_id' => 'event-1', 'type' => 'catalog.published', 'application_id' => 'app-1', 'occurred_at' => '2026-10-28T12:00:00Z', 'subject' => null], JSON_THROW_ON_ERROR);
    }

    private function requestWithSession(?string $id = null): Request
    {
        $request = Request::create('https://consumer.test/');
        $store = new Store('consumer_session', new ArraySessionHandler(120));
        $store->start();
        if ($id) {
            $store->put('identity.session', $id);
        }
        $request->setLaravelSession($store);

        return $request;
    }
}
