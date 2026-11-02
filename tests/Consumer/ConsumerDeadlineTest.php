<?php

declare(strict_types=1);

use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

uses(TestCase::class);

it('withholds directory data when the local session expires during the provider read', function (): void {
    $row = new IdentitySession([
        'id' => 'deadline-session', 'subject' => 'person-1', 'sid' => 'sid-1',
        'selection' => ['selected' => true], 'context_version' => 2, 'token_generation' => 1,
        'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addSecond(),
    ]);
    $row->token_vault = $this->graph()->make(IdentityVault::class)->seal([
        'access_token' => 'synthetic-actor-token', 'expires_at' => now()->timestamp + 600,
    ], 'session:deadline-session');
    $liveness = $this->graph()->make(SessionManager::class);
    expect($liveness->live($row))->toBeTrue();
    $sessions = $this->createStub(SessionManager::class);
    $sessions->method('current')->willReturnCallback(fn () => clone $row);
    $sessions->method('live')->willReturnCallback($liveness->live(...));
    $rows = $this->createStub(SessionRepository::class);
    $rows->method('find')->willReturnCallback(fn () => clone $row);
    $this->graph()->instance(SessionManager::class, $sessions);
    $this->graph()->instance(SessionRepository::class, $rows);
    Http::preventStrayRequests();
    Http::fake(function () {
        $this->travel(2)->seconds();

        return Http::response([
            'contract' => 'platform-consumer-result.v1', 'issuer' => 'https://identity.test/api/auth',
            'applicationId' => 'app-1', 'clientId' => 'web-1', 'subject' => 'person-1',
            'centralSessionId' => 'sid-1', 'data' => ['items' => [], 'nextCursor' => null],
        ]);
    });
    try {
        $this->graph()->make(ConsumerClient::class)->call(Request::create('/manage/users'), 'directory.query', ['limit' => 10]);
        $this->fail('Directory data was returned after local session expiry.');
    } catch (IdentityException $error) {
        expect($error->errorCode)->toBe('context_changed')
            ->and($error->status)->toBe(409);
    } finally {
        $this->travelBack();
    }
    Http::assertSentCount(1);
});
