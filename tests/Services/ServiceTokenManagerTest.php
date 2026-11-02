<?php

namespace IdentityPlatform\Laravel\Tests\Services;

use IdentityPlatform\Laravel\Services\ServiceTokenManager;
use IdentityPlatform\Laravel\Support\ServiceTargetRegistry;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Http;

class ServiceTokenManagerTest extends TestCase
{
    public function test_named_target_uses_its_own_issuer_and_audience_without_browser_credentials(): void
    {
        $this->assertTrue(class_exists(ServiceTokenManager::class), 'Named service target factory is missing');
        $definition = config('identity.service_targets.reports');
        $definition['origin'] = 'https://worker.test';
        $definition['application_id'] = 'worker-app';
        $registry = new ServiceTargetRegistry(['worker' => $definition], ['array']);
        Http::fake(['https://worker.test/*' => Http::response(['access_token' => 'synthetic', 'token_type' => 'Bearer', 'expires_in' => 60, 'scope' => 'documents.read'])]);
        $client = (new ServiceTokenManager($registry))->target('worker');
        $this->assertSame('synthetic', $client->token());
        Http::assertSent(fn ($request) => $request['resource'] === 'urn:identity-platform:application:worker-app' && $request->hasHeader('Authorization', 'Basic '.base64_encode('worker-1:service-secret')));
    }
}
