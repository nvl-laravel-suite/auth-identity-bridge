<?php

namespace IdentityPlatform\Laravel\Tests\Consumer;

use IdentityPlatform\Laravel\Auth\SessionManager;
use IdentityPlatform\Laravel\Consumer\CommandJournal;
use IdentityPlatform\Laravel\Consumer\ConsumerClient;
use IdentityPlatform\Laravel\Consumer\ConsumerCommand;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\RefreshIdentityUser;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Sync\UserSyncRequest;
use IdentityPlatform\Laravel\Tests\Sync\ProfileFixture;
use IdentityPlatform\Laravel\Tests\TestCase;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

class ManagedClientTest extends TestCase
{
    private IdentitySession $row;

    private function client(bool $sync = false): ConsumerClient
    {
        if ($sync) {
            $this->configure(['identity.consumers.one.sync.enabled' => true]);
        }
        Queue::fake();
        Http::preventStrayRequests();
        $this->row = new IdentitySession(['id' => 'ledger-1', 'subject' => 'actor', 'sid' => 'sid-1', 'selection' => ['selected' => true, 'organizationId' => null, 'roleId' => 'manager'], 'context_version' => 2, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $this->row->token_vault = $this->graph()->make(IdentityVault::class)->seal(['access_token' => 'synthetic-actor-token', 'expires_at' => now()->timestamp + 600], 'session:ledger-1');
        $liveness = $this->graph()->make(SessionManager::class);
        $sessions = $this->createStub(SessionManager::class);
        $sessions->method('current')->willReturnCallback(fn () => clone $this->row);
        $sessions->method('live')->willReturnCallback($liveness->live(...));
        $rows = $this->createStub(SessionRepository::class);
        $rows->method('find')->willReturnCallback(fn () => clone $this->row);
        $this->graph()->instance(SessionManager::class, $sessions);
        $this->graph()->instance(SessionRepository::class, $rows);

        return $this->graph()->make(ConsumerClient::class);
    }

    private function request(): Request
    {
        return Request::create('/people/target', 'POST', ['context_version' => 2]);
    }

    private function input(): array
    {
        return ['userId' => 'target', 'expectedVersion' => 2, 'changes' => ['name' => 'New private name'], 'reason' => 'Private audit reason', 'idempotencyKey' => 'command-1'];
    }

    private function receipt(): array
    {
        return ['id' => 'target', 'version' => 3, 'operation' => 'users.profile.update', 'idempotencyKey' => 'command-1', 'changedFields' => ['name']];
    }

    private function envelope(array $data): array
    {
        return ['contract' => 'platform-consumer-result.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'subject' => 'actor', 'centralSessionId' => 'sid-1', 'data' => $data];
    }

    public function test_retains_before_http_and_only_queues_credential_free_versioned_sync(): void
    {
        $client = $this->client(true);
        Http::fake(function ($request) {
            if (str_ends_with($request->url(), '/profiles.read')) {
                return Http::response([], 503);
            }
            self::assertSame(1, ConsumerCommand::count());
            self::assertSame('retained', ConsumerCommand::first()->state);
            self::assertSame('synthetic-actor-token', $request['token']);
            self::assertSame('manager', $request['roleId']);
            self::assertTrue($request->hasHeader('Authorization', 'Basic '.base64_encode('web-1:secret')));
            self::assertFalse($request->hasHeader('Cookie'));

            return Http::response($this->envelope($this->receipt()));
        });
        $result = $client->updateProfile($this->request(), $this->input());
        self::assertSame('committed', $result->status);
        self::assertSame('pending', $result->refresh);
        self::assertSame($this->receipt(), $result->receipt);
        self::assertSame(1, UserSyncRequest::count());
        Queue::assertPushed(RefreshIdentityUser::class, 1);
        $stored = ConsumerCommand::first()->toJson();
        foreach (['New private name', 'Private audit reason', 'synthetic-actor-token', 'secret'] as $secret) {
            self::assertStringNotContainsString($secret, $stored);
        }
        self::assertSame('committed', ConsumerCommand::first()->state);
    }

    public function test_retention_failure_and_open_transaction_prevent_http(): void
    {
        $client = $this->client();
        Http::fake();
        $connection = (new ConsumerCommand)->getConnection();
        $connection->beginTransaction();
        try {
            $result = $client->updateProfile($this->request(), $this->input());
            self::assertSame('failed', $result->status);
            self::assertSame('recovery_pending', $result->error->kind);
        } finally {
            $connection->rollBack();
        }
        Http::assertNothingSent();
    }

    public function test_unknown_status_denial_stays_unknown_and_later_original_receipt_recovers(): void
    {
        $client = $this->client(true);
        Http::fakeSequence()->push(['error' => ['code' => 'unavailable']], 503)->push(['error' => ['code' => 'mfa_required']], 403)->push($this->envelope(['operation' => 'users.profile.update', 'status' => 'completed', 'data' => $this->receipt()]));
        $unknown = $client->updateProfile($this->request(), $this->input());
        self::assertSame('unknown', $unknown->status);
        $denied = $client->operationStatus($this->request(), $unknown->reference);
        self::assertSame('unknown', $denied->status);
        self::assertSame('mfa', $denied->error->kind);
        $this->row->token_generation++;
        $recovered = $client->operationStatus($this->request(), $unknown->reference);
        self::assertSame('committed', $recovered->status);
        self::assertSame(3, $recovered->receipt['version']);
        self::assertSame(1, ConsumerCommand::count());
        self::assertSame(1, UserSyncRequest::count());
        Http::assertSent(fn ($request) => str_ends_with($request->url(), '/operations/status') && $request['input'] === ['idempotencyKey' => 'command-1']);
    }

    #[DataProvider('outerChanges')]
    public function test_wrong_outer_binding_never_claims_commit(string $field): void
    {
        $client = $this->client();
        Http::fake(['*' => Http::response(array_replace($this->envelope($this->receipt()), [$field => 'foreign']))]);
        self::assertSame('unknown', $client->updateProfile($this->request(), $this->input())->status);
    }

    public static function outerChanges(): array
    {
        return array_map(fn ($field) => [$field], ['issuer', 'applicationId', 'clientId', 'subject', 'centralSessionId', 'contract']);
    }

    #[DataProvider('contextChanges')]
    public function test_postresponse_change_suppresses_private_read_but_retains_commit(string $field): void
    {
        $client = $this->client(true);
        Http::fake(function () use ($field) {
            $this->row->{$field}++;

            return Http::response($this->envelope($this->receipt()));
        });
        $committed = $client->updateProfile($this->request(), $this->input());
        self::assertSame('committed', $committed->status);
        self::assertSame('changed', $committed->context);
        self::assertSame('pending', $committed->refresh);
        $this->row->{$field}--;
        Http::fake(function () use ($field) {
            $this->row->{$field}++;

            return Http::response($this->envelope(['id' => 'target', 'version' => 3, 'writableFields' => ['name'], 'fields' => ['name' => 'private']]));
        });
        $read = $client->readProfile($this->request(), ['userId' => 'target']);
        self::assertSame('failed', $read->status);
        self::assertNull($read->data);
        self::assertStringNotContainsString('private', json_encode($read));
    }

    public static function contextChanges(): array
    {
        return [['context_version'], ['token_generation']];
    }

    public function test_invalid_vault_token_has_no_ambient_fallback(): void
    {
        $client = $this->client();
        $this->row->token_vault = $this->graph()->make(IdentityVault::class)->seal(['access_token' => ['not' => 'a token'], 'expires_at' => time() + 600], 'session:ledger-1');
        Http::fake();
        $result = $client->updateProfile($this->request(), $this->input());
        self::assertSame('failed', $result->status);
        self::assertSame('authentication', $result->error->kind);
        self::assertSame(0, ConsumerCommand::count());
        Http::assertNothingSent();
    }

    public function test_metadata_helpers_have_distinct_paths_and_partial_results(): void
    {
        $client = $this->client();
        $receipt = array_replace($this->receipt(), ['operation' => 'users.metadata.update', 'changedFields' => ['adminNotes', 'tags']]);
        Http::fakeSequence()->push($this->envelope(['id' => 'target', 'version' => 2, 'writableFields' => [], 'fields' => ['adminNotes' => null]]))->push($this->envelope($receipt));
        self::assertSame(['adminNotes' => null], $client->readMetadata($this->request(), ['userId' => 'target'])->data['fields']);
        $input = array_replace($this->input(), ['changes' => ['adminNotes' => null, 'tags' => ['z', ' a ']]]);
        $result = $client->updateMetadata($this->request(), $input);
        self::assertSame('committed', $result->status);
        self::assertSame('not_required', $result->refresh);
        Http::assertSent(fn ($request) => str_ends_with($request->url(), '/app/users/metadata/read'));
        Http::assertSent(fn ($request) => str_ends_with($request->url(), '/app/users/metadata/update') && $request['input']['changes'] === ['adminNotes' => null, 'tags' => ['a', 'z']]);
        self::assertSame(['adminNotes' => null, 'tags' => ['z', ' a ']], $input['changes']);
    }

    public function test_provider_refusal_is_safe_failed_and_preserves_caller_input(): void
    {
        $client = $this->client();
        $input = $this->input();
        Http::fake(['*' => Http::response(['error' => ['code' => 'consumer_profile_field_denied', 'message' => 'must not expose private provider internals']], 403)]);
        $result = $client->updateProfile($this->request(), $input);
        self::assertSame('failed', $result->status);
        self::assertSame('refusal', $result->error->kind);
        self::assertSame('consumer_profile_field_denied', $result->error->code);
        self::assertSame($this->input(), $input);
        self::assertStringNotContainsString('private', json_encode($result));
        self::assertSame('failed', ConsumerCommand::first()->state);
    }

    public function test_invalid_request_never_retains_or_sends(): void
    {
        $client = $this->client();
        Http::fake();
        self::assertSame('validation', $client->updateProfile($this->request(), array_replace($this->input(), ['changes' => ['profileCompleted' => true]]))->error->kind);
        self::assertSame(0, ConsumerCommand::count());
        Http::assertNothingSent();
    }

    public function test_repeat_original_key_queries_status_without_repeating_mutation_or_refetch_intent(): void
    {
        $client = $this->client(true);
        $writes = 0;
        $status = 0;
        Http::fake(function ($request) use (&$writes, &$status) {
            if (str_ends_with($request->url(), '/profiles.read')) {
                return Http::response([], 503);
            }
            if (str_ends_with($request->url(), '/operations/status')) {
                $status++;

                return Http::response($this->envelope(['operation' => 'users.profile.update', 'status' => 'completed', 'data' => $this->receipt()]));
            }
            $writes++;

            return Http::response($this->envelope($this->receipt()));
        });
        $first = $client->updateProfile($this->request(), $this->input());
        $second = $client->updateProfile($this->request(), $this->input());
        self::assertSame('committed', $first->status);
        self::assertSame('committed', $second->status);
        self::assertSame(1, $writes);
        self::assertSame(1, $status);
        self::assertSame(1, ConsumerCommand::count());
        self::assertSame(1, UserSyncRequest::first()->generation);
        Queue::assertPushed(RefreshIdentityUser::class, 1);
    }

    public function test_retention_failure_and_changed_context_during_retention_do_not_send(): void
    {
        $this->client();
        $real = $this->graph()->make(CommandJournal::class);
        $journal = $this->createStub(CommandJournal::class);
        $journal->method('retain')->willReturnCallback(function ($reference) use ($real) {
            $row = $real->retain($reference);
            $this->row->token_generation++;

            return $row;
        });
        $this->graph()->instance(CommandJournal::class, $journal);
        Http::fake();
        $result = $this->graph()->make(ConsumerClient::class)->updateProfile($this->request(), $this->input());
        self::assertSame('failed', $result->status);
        self::assertSame('context_changed', $result->error->kind);
        Http::assertNothingSent();
        $failed = $this->createStub(CommandJournal::class);
        $failed->method('retain')->willThrowException(new \RuntimeException('private store error'));
        $this->graph()->instance(CommandJournal::class, $failed);
        $result = $this->graph()->make(ConsumerClient::class)->updateProfile($this->request(), $this->input());
        self::assertSame('failed', $result->status);
        self::assertSame('recovery_pending', $result->error->kind);
        self::assertStringNotContainsString('private', json_encode($result));
        Http::assertNothingSent();
    }

    public function test_status_reference_cannot_switch_actor_context_target_or_field_names(): void
    {
        $client = $this->client();
        Http::fake(['*' => Http::response([], 503)]);
        $original = $client->updateProfile($this->request(), $this->input())->reference;
        Http::fake();
        foreach ([['subject' => 'other'], ['bindingHash' => str_repeat('x', 64)], ['userId' => 'other'], ['changedFields' => ['bio']], ['reason' => 'private'], ['contextVersion' => 3]] as $patch) {
            $result = $client->operationStatus($this->request(), array_replace($original, $patch));
            self::assertSame('unknown', $result->status);
            self::assertNull($result->reference);
        }
        $this->row->subject = 'different';
        self::assertNull($client->operationStatus($this->request(), $original)->reference);
        Http::assertNothingSent();
    }

    public function test_invalid_status_receipt_and_pending_never_invent_commit(): void
    {
        $client = $this->client();
        Http::fakeSequence()->push([], 503)
            ->push($this->envelope(['operation' => 'users.profile.update', 'status' => 'pending', 'data' => null]))
            ->push($this->envelope(['operation' => 'users.profile.update', 'status' => 'completed', 'data' => array_replace($this->receipt(), ['version' => 19])]))
            ->push($this->envelope(['operation' => 'users.metadata.update', 'status' => 'pending', 'data' => null]));
        $original = $client->updateProfile($this->request(), $this->input())->reference;
        self::assertSame('pending', $client->operationStatus($this->request(), $original)->status);
        self::assertSame('unknown', $client->operationStatus($this->request(), $original)->status);
        self::assertSame('unknown', $client->operationStatus($this->request(), $original)->status);
    }

    public function test_confirmed_commit_survives_later_status_authority_refusal(): void
    {
        $client = $this->client();
        Http::fakeSequence()->push($this->envelope($this->receipt()))->push(['error' => ['code' => 'mfa_required']], 403);
        $first = $client->updateProfile($this->request(), $this->input());
        $later = $client->operationStatus($this->request(), $first->reference);
        self::assertSame('committed', $later->status);
        self::assertSame($first->receipt, $later->receipt);
        self::assertSame('mfa', $later->error->kind);
        Http::assertSentCount(2);
    }

    public function test_retained_confirmed_commit_cannot_regress_to_pending(): void
    {
        $client = $this->client();
        Http::fakeSequence()->push($this->envelope($this->receipt()))->push($this->envelope(['operation' => 'users.profile.update', 'status' => 'pending', 'data' => null]));
        $first = $client->updateProfile($this->request(), $this->input());
        $later = $client->operationStatus($this->request(), $first->reference);
        self::assertSame('committed', $later->status);
        self::assertSame($first->receipt, $later->receipt);
    }

    public function test_retained_graph_journal_uses_original_connection_and_other_binding_cannot_read_it(): void
    {
        $client = $this->client();
        Http::fake(['*' => Http::response([], 503)]);
        $reference = $client->updateProfile($this->request(), $this->input())->reference;
        $journal = $this->graph()->make(CommandJournal::class);
        config(['identity.connection' => 'nonexistent']);
        self::assertSame('sqlite', $journal->original($reference)->getConnectionName());
        config(['identity.connection' => null]);
        $this->configure(['identity.consumers.one.browser.client_id' => 'another-client']);
        $other = $this->graph()->make(CommandJournal::class);
        self::assertSame([], $other->pendingRefreshIds());
        $this->expectException(IdentityException::class);
        $other->original($reference);
    }

    public function test_missing_sync_work_cannot_claim_refreshed(): void
    {
        $client = $this->client(true);
        Http::fake(['*' => Http::response($this->envelope($this->receipt()))]);
        $client->updateProfile($this->request(), $this->input());
        UserSyncRequest::query()->delete();
        self::assertSame('pending', $this->graph()->make(CommandJournal::class)->refresh(ConsumerCommand::first()->id));
    }

    public function test_native_model_without_sync_is_explicitly_not_configured_even_after_work_was_created(): void
    {
        $this->configure(['identity.consumers.one.users.model' => ManagedNativeUser::class, 'identity.consumers.one.users.fields' => ['name' => 'name']]);
        $client = $this->client(true);
        Http::fake(['*' => Http::response($this->envelope($this->receipt()))]);
        $first = $client->updateProfile($this->request(), $this->input());
        self::assertSame('pending', $first->refresh);
        $this->configure(['identity.consumers.one.sync.enabled' => false]);
        self::assertSame('not_configured', $this->graph()->make(CommandJournal::class)->refresh(ConsumerCommand::first()->id));
        $this->configure(['identity.consumers.one.sync.enabled' => true]);
        self::assertSame('pending', $this->graph()->make(CommandJournal::class)->refresh(ConsumerCommand::first()->id));
    }

    #[DataProvider('badTokens')]
    public function test_malformed_or_expired_actor_tokens_fail_before_retaining(mixed $token, int $expiry): void
    {
        $client = $this->client();
        $this->row->token_vault = $this->graph()->make(IdentityVault::class)->seal(['access_token' => $token, 'expires_at' => time() + $expiry], 'session:ledger-1');
        Http::fake();
        $result = $client->updateProfile($this->request(), $this->input());
        self::assertSame('failed', $result->status);
        self::assertSame('authentication', $result->error->kind);
        self::assertSame(0, ConsumerCommand::count());
        Http::assertNothingSent();
    }

    public static function badTokens(): array
    {
        return [['', 60], [null, 60], ["has\r\ncontrol", 60], ['synthetic-token', -1], ['synthetic-token', 0]];
    }

    #[DataProvider('jsonReadKinds')]
    public function test_http_boundary_preserves_json_object_and_list_kinds(string $operation, string $json, string $status): void
    {
        $client = $this->client();
        $envelope = json_encode($this->envelope(['placeholder' => true]));
        $envelope = str_replace('{"placeholder":true}', $json, $envelope);
        Http::fake(['*' => Http::response($envelope, 200, ['Content-Type' => 'application/json'])]);
        $result = $operation === 'users.profile.read' ? $client->readProfile($this->request(), ['userId' => 'target']) : $client->readMetadata($this->request(), ['userId' => 'target']);
        self::assertSame($status, $result->status);
        if ($status === 'read') {
            self::assertEquals(json_decode($json), json_decode(json_encode($result))->data);
        }
    }

    public static function jsonReadKinds(): array
    {
        return [
            ['users.profile.read', '{"id":"target","version":2,"fields":{}}', 'failed'],
            ['users.metadata.read', '{"id":"target","version":2,"fields":{}}', 'failed'],
            ['users.profile.read', '{"id":"target","version":2,"writableFields":{},"fields":{}}', 'failed'],
            ['users.metadata.read', '{"id":"target","version":2,"writableFields":{"0":"tags"},"fields":{"tags":[]}}', 'failed'],
            ['users.profile.read', '{"id":"target","version":2,"writableFields":["name"],"fields":{"name":"Person","phone":null}}', 'read'],
            ['users.profile.read', '{"id":"target","version":2,"writableFields":["accountType","name","phone"],"fields":{"accountType":"company","name":"Person","phone":null,"profileCompleted":true}}', 'read'],
            ['users.metadata.read', '{"id":"target","version":2,"writableFields":["adminNotes","tags"],"fields":{"adminNotes":null,"tags":[]}}', 'read'],
            ['users.profile.read', '{"id":"target","version":2,"writableFields":[],"fields":{}}', 'read'],
            ['users.profile.read', '{"id":"target","version":2,"writableFields":[],"fields":[]}', 'failed'],
            ['users.profile.read', '{"id":"target","version":2,"writableFields":[],"fields":{"socialLinks":{}}}', 'read'],
            ['users.profile.read', '{"id":"target","version":2,"writableFields":[],"fields":{"socialLinks":[]}}', 'failed'],
            ['users.profile.read', '{"id":"target","version":2,"writableFields":[],"fields":{"socialLinks":{"0":"https://example.test/"}}}', 'read'],
            ['users.metadata.read', '{"id":"target","version":2,"writableFields":[],"fields":{"tags":[]}}', 'read'],
            ['users.metadata.read', '{"id":"target","version":2,"writableFields":[],"fields":{"tags":{}}}', 'failed'],
        ];
    }

    public function test_legacy_read_returns_the_same_validated_current_hint(): void
    {
        $client = $this->client();
        $data = ['id' => 'target', 'version' => 2, 'fields' => ['name' => 'Person'], 'writableFields' => ['name']];
        Http::fake(['*' => Http::response($this->envelope($data))]);
        self::assertSame($data, $client->call($this->request(), 'users.profile.read', ['userId' => 'target']));
    }

    #[DataProvider('outerChanges')]
    public function test_hinted_read_still_binds_the_original_actor_envelope(string $field): void
    {
        $client = $this->client();
        $data = ['id' => 'target', 'version' => 2, 'fields' => ['name' => 'Private'], 'writableFields' => ['name']];
        Http::fake(['*' => Http::response(array_replace($this->envelope($data), [$field => 'foreign']))]);
        $result = $client->readProfile($this->request(), ['userId' => 'target']);
        self::assertSame('failed', $result->status);
        self::assertNull($result->data);
    }

    public function test_empty_social_links_send_as_json_object_and_receipt_fields_require_json_list(): void
    {
        $client = $this->client();
        Http::fake(function ($request) {
            $body = json_decode($request->body());
            self::assertInstanceOf(\stdClass::class, $body->input->changes->socialLinks);
            $receipt = $this->receipt();
            $receipt['changedFields'] = (object) ['0' => 'socialLinks'];

            return Http::response($this->envelope($receipt));
        });
        self::assertSame('unknown', $client->updateProfile($this->request(), array_replace($this->input(), ['changes' => ['socialLinks' => []]]))->status);
    }

    #[DataProvider('deadlineFences')]
    public function test_every_managed_fence_observes_original_session_and_token_deadlines(string $deadline, string $fence): void
    {
        $this->freezeTime();
        try {
            $client = $this->client();
            $seconds = $fence === 'initial' ? -1 : 1;
            $config = $this->graph()->make(IdentityConfig::class);
            match ($deadline) {
                'absolute' => $this->row->started_at = now()->subSeconds($config->value('local.absolute_seconds', 43200) - $seconds),
                'idle' => $this->row->last_activity_at = now()->subSeconds($config->value('local.idle_seconds', 1800) - $seconds),
                'stored' => $this->row->expires_at = now()->addSeconds($seconds),
                'token' => $this->row->token_vault = $this->graph()->make(IdentityVault::class)->seal(['access_token' => 'synthetic-actor-token', 'expires_at' => now()->timestamp + $seconds], 'session:ledger-1'),
            };
            if ($fence === 'retention') {
                $real = $this->graph()->make(CommandJournal::class);
                $journal = $this->createStub(CommandJournal::class);
                $journal->method('retain')->willReturnCallback(function ($reference) use ($real) {
                    $command = $real->retain($reference);
                    $this->travel(2)->seconds();

                    return $command;
                });
                $this->graph()->instance(CommandJournal::class, $journal);
                $client = $this->graph()->make(ConsumerClient::class);
            }
            Http::fake(function () use ($fence) {
                $this->travel(2)->seconds();

                return Http::response($this->envelope($fence === 'read' ? ['id' => 'target', 'version' => 2, 'writableFields' => [], 'fields' => ['name' => 'private after deadline']] : $this->receipt()));
            });
            $result = $fence === 'read' ? $client->readProfile($this->request(), ['userId' => 'target']) : $client->updateProfile($this->request(), $this->input());
            if ($fence === 'committed') {
                self::assertSame('committed', $result->status);
                self::assertSame('changed', $result->context);
                self::assertSame($this->receipt(), $result->receipt);
            } else {
                self::assertSame('failed', $result->status);
                self::assertStringNotContainsString('private after deadline', json_encode($result));
            }
            if (in_array($fence, ['initial', 'retention'], true)) {
                Http::assertNothingSent();
            }
        } finally {
            $this->travelBack();
        }
    }

    public static function deadlineFences(): array
    {
        $cases = [];
        foreach (['absolute', 'idle', 'stored', 'token'] as $deadline) {
            foreach (['initial', 'retention', 'read', 'committed'] as $fence) {
                $cases[$deadline.'-'.$fence] = [$deadline, $fence];
            }
        }

        return $cases;
    }

    public function test_operation_pending_retains_unknown_original_command_and_recovers_without_resubmission(): void
    {
        $client = $this->client();
        Http::fakeSequence()->push(['error' => ['code' => 'operation_pending']], 409)
            ->push($this->envelope(['operation' => 'users.profile.update', 'status' => 'completed', 'data' => $this->receipt()]));
        $pending = $client->updateProfile($this->request(), $this->input());
        self::assertSame('unknown', $pending->status);
        self::assertSame('recovery_pending', $pending->error->kind);
        self::assertSame('operation_pending', $pending->error->code);
        self::assertSame('unknown', ConsumerCommand::first()->state);
        self::assertSame('command-1', $pending->reference['idempotencyKey']);
        $recovered = $client->updateProfile($this->request(), $this->input());
        self::assertSame('committed', $recovered->status);
        self::assertSame($pending->reference, $recovered->reference);
        self::assertSame(1, ConsumerCommand::count());
        Http::assertSentCount(2);
        Http::assertSent(fn ($request) => str_ends_with($request->url(), '/operations/status') && $request['input'] === ['idempotencyKey' => 'command-1']);
    }

    public function test_committed_refresh_failure_retains_one_intent_and_only_validated_snapshot_maps_native_fields(): void
    {
        Schema::create('managed_native_users', function (Blueprint $table) {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->string('application_note')->default('owned by host');
            $table->timestamps();
        });
        $this->configure(['identity.consumers.one.users.model' => ManagedNativeUser::class, 'identity.consumers.one.users.fields' => ['name' => 'name', 'email' => 'email']]);
        $client = $this->client(true);
        $projection = $this->graph()->make(UserSynchronizer::class)->sync(['sub' => 'target', 'name' => 'Before', 'email' => 'target@example.test']);
        $native = $this->graph()->make(IdentityUserResolver::class)->resolve($projection);
        $syncReply = [];
        $syncStatus = 503;
        Http::fake(function ($request) use (&$syncReply, &$syncStatus) {
            return str_ends_with($request->url(), '/profiles.read') ? Http::response($syncReply, $syncStatus) : Http::response($this->envelope($this->receipt()));
        });
        $result = $client->updateProfile($this->request(), $this->input());
        self::assertSame('committed', $result->status);
        self::assertSame('pending', $result->refresh);
        self::assertSame('Before', $native->refresh()->name);
        $journal = $this->graph()->make(CommandJournal::class);
        $id = ConsumerCommand::first()->id;
        self::assertSame([$id], $journal->pendingRefreshIds());
        $snapshot = ['contract' => 'platform-consumer-sync.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'profiles' => [['subject' => 'target', 'version' => 23, 'state' => 'active', 'profile' => ProfileFixture::profile(['name' => 'Validated later revision', 'email' => 'target@example.test'])]], 'nextCursor' => null];
        $syncReply = array_replace($snapshot, ['clientId' => 'foreign']);
        $syncStatus = 200;
        self::assertSame('pending', $journal->refresh($id));
        self::assertSame('Before', $native->refresh()->name);
        $syncReply = $snapshot;
        self::assertSame('refreshed', $journal->refresh($id), UserSyncRequest::first()->last_error ?? 'no recorded sync error');
        self::assertSame('Validated later revision', $native->refresh()->name);
        self::assertSame('owned by host', $native->application_note);
        self::assertSame([], $journal->pendingRefreshIds());
        self::assertSame(1, UserSyncRequest::count());
        Http::assertSent(fn ($request) => str_ends_with($request->url(), '/profiles.read') && ! isset($request['token']));
    }
}

class ManagedNativeUser extends User
{
    protected $table = 'managed_native_users';

    protected $guarded = [];
}
