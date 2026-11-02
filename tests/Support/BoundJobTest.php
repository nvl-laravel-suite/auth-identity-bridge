<?php

namespace IdentityPlatform\Laravel\Tests\Support;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Sync\RefreshIdentityUser;
use IdentityPlatform\Laravel\Sync\UserSyncRequest;
use IdentityPlatform\Laravel\Sync\UserSyncWorkRepository;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\Http;

class BoundJobTest extends TestCase
{
    public function test_present_work_with_removed_binding_refuses_before_constructing_a_manager(): void
    {
        UserSyncRequest::create(['id' => 'orphan', 'binding_hash' => str_repeat('f', 64), 'issuer' => 'https://identity.test/api/auth', 'subject' => 'person']);
        $this->app->forgetInstance(ConsumerGraph::class);
        $this->expectExceptionObject(new IdentityException('unknown_consumer_binding'));
        $this->app->call([new RefreshIdentityUser('orphan'), 'handle']);
    }

    public function test_genuinely_missing_work_is_idempotent_without_http_or_selected_context(): void
    {
        $this->app->forgetInstance(ConsumerGraph::class);
        $this->app->call([new RefreshIdentityUser('missing'), 'handle']);
        $this->assertDatabaseCount('identity_user_sync_requests', 0);
    }

    public function test_queued_refetch_loads_row_binding_before_selecting_credentials_without_http_state(): void
    {
        $second = config('identity.consumers.one');
        $second['app_origin'] = 'https://second.test';
        $second['browser']['client_id'] = 'web-2';
        $second['browser']['client_secret'] = 'second-secret';
        $second['browser']['redirect_uri'] = 'https://second.test/auth/callback';
        $second['browser']['post_logout_redirect_uri'] = 'https://second.test/signed-out';
        $second['routes']['event_uri'] = 'https://second.test/events';
        $second['routes']['backchannel_logout_uri'] = 'https://second.test/backchannel';
        $second['routes']['guard'] = 'identity_two';
        $second['sync']['enabled'] = true;
        $this->configure(['identity.consumers.two' => $second]);
        $two = app(Identity::class)->consumer('two');
        $row = $two->make(UserSyncWorkRepository::class)->request('person');
        Http::fake(['https://identity.test/api/consumer-sync/v1/profiles.read' => Http::response(['contract' => 'platform-consumer-sync.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-2', 'policyVersion' => 1, 'profiles' => [['subject' => 'person', 'version' => 1, 'state' => 'revoked', 'profile' => null]], 'nextCursor' => null])]);
        $this->app->forgetInstance(ConsumerGraph::class);
        $this->app->call([new RefreshIdentityUser($row->id), 'handle']);
        $this->assertSame($row->generation, $row->refresh()->completed_generation);
        Http::assertSent(fn ($request) => $request->hasHeader('Authorization', 'Basic '.base64_encode('web-2:second-secret')));
    }
}
