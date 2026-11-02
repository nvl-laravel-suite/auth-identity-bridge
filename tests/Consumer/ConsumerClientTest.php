<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Consumer;

use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Delegation\IdentityDelegation;
use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Tests\Sync\ProfileFixture;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

class ConsumerClientTest extends TestCase
{
    private function client(): ConsumerClient
    {
        $row = new IdentitySession(['id' => 'ledger-1', 'subject' => 'person-1', 'sid' => 'sid-1', 'selection' => ['selected' => true], 'context_version' => 2, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $row->token_vault = app(IdentityVault::class)->seal(['access_token' => 'synthetic-actor-token'], 'session:ledger-1');
        $liveness = app(SessionManager::class);
        $sessions = $this->createStub(SessionManager::class);
        $sessions->method('current')->willReturn($row);
        $sessions->method('live')->willReturnCallback($liveness->live(...));
        $this->graph()->instance(SessionManager::class, $sessions);
        $repository = $this->createStub(SessionRepository::class);
        $repository->method('find')->willReturn($row);
        $this->graph()->instance(SessionRepository::class, $repository);

        return app(ConsumerClient::class);
    }

    private function providerResult(): array
    {
        return ['contract' => 'platform-consumer-result.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'subject' => 'person-1', 'centralSessionId' => 'sid-1', 'data' => [...ProfileFixture::consumer(['name' => 'Synthetic person', 'email' => 'person@example.test', 'locale' => 'en']), 'id' => 'person-1', 'version' => 1]];
    }

    public function test_consumer_read_uses_only_server_vault_actor_and_pinned_client(): void
    {
        $client = $this->client();
        Http::fake(['https://identity.test/api/consumer/v1/self/read' => Http::response($this->providerResult())]);
        $result = $client->call(Request::create('/account'), 'profile.read');
        self::assertSame('Synthetic person', $result['name']);
        Http::assertSent(fn ($request) => $request->hasHeader('Authorization', 'Basic '.base64_encode('web-1:secret')) && $request['token'] === 'synthetic-actor-token' && ! $request->hasHeader('Cookie'));
    }

    public function test_rich_profile_read_and_partial_update_preserve_all_shared_response_fields(): void
    {
        $client = $this->client();
        $reply = $this->providerResult();
        $reply['data'] = array_replace($reply['data'], ['timezone' => 'Europe/Sofia', 'accountType' => 'company', 'phone' => '+359888123456', 'organizationName' => 'Example', 'position' => 'Engineer', 'bio' => 'Biography', 'dateOfBirth' => '2000-02-29', 'gender' => 'other', 'country' => 'BG', 'socialLinks' => ['site' => 'https://example.test/me'], 'profileCompleted' => true]);
        Http::fake(['https://identity.test/api/consumer/v1/self/read' => Http::response($reply)]);
        $this->assertSame($reply['data'], $client->call(Request::create('/account'), 'profile.read'));
        $updated = $reply;
        $updated['data']['phone'] = null;
        $updated['data']['version'] = 2;
        Http::fake(['https://identity.test/api/consumer/v1/self/profile' => Http::response($updated)]);
        $input = ['phone' => null, 'expectedVersion' => 1, 'idempotencyKey' => 'profile-operation'];
        $this->assertSame($updated['data'], $client->call(Request::create('/account', 'POST', ['context_version' => 2]), 'profile.update', $input));
        Http::assertSent(fn ($request) => $request->url() === 'https://identity.test/api/consumer/v1/self/profile' && $request['input'] === $input);
    }

    public function test_rich_directory_pages_and_access_detail_preserve_provider_facts_with_separate_transport_bound(): void
    {
        $client = $this->client();
        $person = array_replace($this->providerResult()['data'], ['phone' => '+359888123456', 'bio' => str_repeat('b', 2000), 'accountType' => 'company', 'organizationName' => 'Example', 'active' => true, 'status' => 'active', 'grantVersion' => 1]);
        $person['socialLinks'] = [];
        for ($link = 0; $link < 20; $link++) {
            $person['socialLinks']['site-'.$link] = 'https://social.example.test/'.str_repeat('s', 2000);
        }
        $items = [];
        for ($index = 0; $index < 100; $index++) {
            $items[] = array_replace($person, ['id' => 'person-'.$index]);
        }
        $reply = $this->providerResult();
        $reply['data'] = ['items' => $items, 'nextCursor' => null];
        Http::fake(['https://identity.test/api/consumer/v1/app/users/query' => Http::response($reply), 'https://identity.test/api/ordinary' => Http::response($reply)]);
        $this->assertSame($reply['data'], $client->call(Request::create('/people'), 'directory.query', ['limit' => 100]));
        try {
            app(IdentityHttp::class)->get('/api/ordinary');
            $this->fail('Generic ordinary response bound was weakened');
        } catch (IdentityException $error) {
            $this->assertSame('response_too_large', $error->errorCode);
        }
        $reply['data'] = [...$person, 'roles' => ['role-1'], 'allow' => ['documents.read'], 'deny' => []];
        Http::fake(['*' => Http::response($reply)]);
        foreach (['directory.read', 'access.read'] as $operation) {
            $this->assertSame($reply['data'], $client->call(Request::create('/people/person-1'), $operation, ['userId' => 'person-1']));
        }
    }

    public function test_bounded_option_reads_use_pinned_transport_and_report_cursor_rejection(): void
    {
        $client = $this->client();
        $page = ['items' => [], 'nextCursor' => null, 'selected' => []];
        $reject = false;
        Http::fake(function () use (&$reject, $page) {
            return $reject ? Http::response(['error' => ['code' => 'invalid_cursor']], 409) : Http::response(array_replace($this->providerResult(), ['data' => $page]));
        });
        foreach (['roles.options.query' => 'app/roles/options', 'permissions.options.query' => 'app/permissions/options'] as $operation => $path) {
            self::assertSame($page, $client->call(Request::create('/choices'), $operation, ['selectedValues' => []]));
            Http::assertSent(fn ($request) => $request->url() === 'https://identity.test/api/consumer/v1/'.$path && $request['token'] === 'synthetic-actor-token' && ! $request->hasHeader('Cookie'));
        }
        $reject = true;
        try {
            $client->call(Request::create('/choices'), 'roles.options.query', ['cursor' => 'opaque']);
            self::fail('Cursor rejection was not returned');
        } catch (IdentityException $error) {
            self::assertSame('invalid_cursor', $error->errorCode);
        }
    }

    public function test_option_memo_is_request_local_and_bound_to_token_generation(): void
    {
        $client = $this->client();
        $reply = array_replace($this->providerResult(), ['data' => ['items' => [], 'nextCursor' => null, 'selected' => []]]);
        Http::fake(['*' => Http::response($reply)]);
        $request = Request::create('/choices');
        $client->call($request, 'roles.options.query', ['selectedValues' => []]);
        $client->call($request, 'roles.options.query', ['selectedValues' => []]);
        Http::assertSentCount(1);
        $row = app(SessionRepository::class)->find('ledger-1');
        $row->token_generation++;
        $client->call($request, 'roles.options.query', ['selectedValues' => []]);
        Http::assertSentCount(2);
        $client->call(Request::create('/choices'), 'roles.options.query', ['selectedValues' => []]);
        Http::assertSentCount(3);
    }

    public function test_option_memo_never_bypasses_a_new_overlay_guard(): void
    {
        $active = false;
        $overlays = $this->createStub(OverlayRepository::class);
        $overlays->method('find')->willReturnCallback(function () use (&$active) {
            return $active ? new IdentityDelegation(['id' => 'ledger-1', 'status' => 'active']) : null;
        });
        $this->graph()->instance(OverlayRepository::class, $overlays);
        $client = $this->client();
        Http::fake(['*' => Http::response(array_replace($this->providerResult(), ['data' => ['items' => [], 'nextCursor' => null, 'selected' => []]]))]);
        $request = Request::create('/choices');
        $client->call($request, 'roles.options.query', ['selectedValues' => []]);
        $active = true;
        try {
            $client->call($request, 'roles.options.query', ['selectedValues' => []]);
            self::fail('Cached option bypassed overlay fence');
        } catch (IdentityException $error) {
            self::assertSame('delegation_control_plane_forbidden', $error->errorCode);
        }
        Http::assertSentCount(1);
    }

    public function test_mutation_is_never_served_from_the_option_memo(): void
    {
        $client = $this->client();
        Http::fake(['*' => Http::response(array_replace($this->providerResult(), ['data' => array_replace($this->providerResult()['data'], ['version' => 2])]))]);
        $request = Request::create('/account', 'POST', ['context_version' => 2]);
        $client->call($request, 'profile.update', ['expectedVersion' => 1]);
        $client->call($request, 'profile.update', ['expectedVersion' => 1]);
        Http::assertSentCount(2);
    }

    public static function optionMutationAttempts(): array
    {
        return ['roles after save' => ['roles.options.query', 'saved'], 'roles after provider refusal' => ['roles.options.query', 'refused'], 'roles after stale form' => ['roles.options.query', 'stale'],
            'permissions after save' => ['permissions.options.query', 'saved'], 'permissions after provider refusal' => ['permissions.options.query', 'refused'], 'permissions after stale form' => ['permissions.options.query', 'stale']];
    }

    #[DataProvider('optionMutationAttempts')]
    public function test_mutation_attempt_clears_prior_option_reads(string $operation, string $outcome): void
    {
        $client = $this->client();
        $reads = 0;
        $writes = 0;
        Http::fake(function ($request) use (&$reads, &$writes, $outcome) {
            if (str_ends_with($request->url(), '/self/profile')) {
                $writes++;

                return $outcome === 'refused' ? Http::response(['error' => ['code' => 'version_conflict']], 409) : Http::response(array_replace($this->providerResult(), ['data' => array_replace($this->providerResult()['data'], ['version' => 2])]));
            }
            $reads++;
            $roles = str_ends_with($request->url(), '/roles/options');

            return Http::response(array_replace($this->providerResult(), ['data' => ['items' => $reads === 1 ? [] : [$roles ? ['value' => 'role-1', 'label' => 'Current reader', 'hint' => 'reader'] : ['value' => 'documents.read', 'label' => 'documents.read', 'hint' => 'Current description']], 'nextCursor' => null, 'selected' => []]]));
        });
        $request = Request::create('/choices', 'POST', ['context_version' => $outcome === 'stale' ? 1 : 2]);
        self::assertSame([], $client->call($request, $operation, ['selectedValues' => []])['items']);
        $client->call($request, $operation, ['selectedValues' => []]);
        self::assertSame(1, $reads);
        try {
            $client->call($request, 'profile.update', ['expectedVersion' => 1]);
            self::assertSame('saved', $outcome);
        } catch (IdentityException $error) {
            self::assertSame($outcome === 'stale' ? 'context_changed' : 'version_conflict', $error->errorCode);
        }
        $current = $client->call($request, $operation, ['selectedValues' => []]);
        self::assertCount(1, $current['items']);
        self::assertSame(2, $reads);
        self::assertSame($outcome === 'stale' ? 0 : 1, $writes);
    }

    public function test_foreign_result_cannot_become_local_profile(): void
    {
        $client = $this->client();
        Http::fake(['*' => Http::response(array_replace($this->providerResult(), ['subject' => 'other-person']))]);
        $this->expectException(IdentityException::class);
        $client->call(Request::create('/account'), 'profile.read');
    }

    public function test_stale_tab_cannot_issue_management_write(): void
    {
        $client = $this->client();
        Http::fake();
        try {
            $client->call(Request::create('/account', 'POST', ['context_version' => 1]), 'profile.update', ['name' => 'Changed']);
            self::fail('Stale context was accepted');
        } catch (IdentityException $error) {
            self::assertSame('context_changed', $error->errorCode);
        }
        Http::assertNothingSent();
    }
}
