<?php

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Callbacks\CallbackReceiver;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Sync\RefreshIdentityUser;
use IdentityPlatform\Laravel\Sync\UserProjectionRepository;
use IdentityPlatform\Laravel\Sync\UserSnapshotBatch;
use IdentityPlatform\Laravel\Sync\UserSnapshotClient;
use IdentityPlatform\Laravel\Sync\UserSnapshotRepository;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Sync\UserSyncManager;
use IdentityPlatform\Laravel\Sync\UserSyncRequest;
use IdentityPlatform\Laravel\Tests\Support\FixtureNativeFactory;
use IdentityPlatform\Laravel\Tests\TestCase;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use IdentityPlatform\Laravel\Users\NativeUserRepository;
use IdentityPlatform\Laravel\Users\ProjectionOwnership;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

class SyncedNativeUser extends User
{
    protected $table = 'synced_native_users';

    protected $guarded = [];
}
class CustomMappedUser extends User
{
    protected $table = 'custom_mapped_users';

    protected $guarded = [];
}

class UserSnapshotTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('synced_native_users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email');
            $table->text('avatar_url')->nullable();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('identity_status')->default('active');
            $table->string('local_role')->default('local-reader');
            $table->timestamps();
        });
        $this->configure(['identity.consumers.one.sync.enabled' => true, 'identity.consumers.one.sync.provision_missing' => true, 'identity.consumers.one.users.model' => SyncedNativeUser::class,
            'identity.consumers.one.users.fields' => ['name' => 'name', 'email' => 'email', 'picture' => 'avatar_url', 'email_verified_at' => 'email_verified_at', 'state' => 'identity_status']]);
        Http::preventStrayRequests();
    }

    private function envelope(int $version = 2, string $state = 'active', int $policy = 1): array
    {
        return ['contract' => 'platform-consumer-sync.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => $policy,
            'profiles' => [['subject' => 'person', 'version' => $version, 'state' => $state, 'profile' => in_array($state, ['revoked', 'deleted'], true) ? null :
                ProfileFixture::profile(['picture' => 'https://images.example.test/avatar.png'])]], 'nextCursor' => null];
    }

    private function batch(array $envelope): UserSnapshotBatch
    {
        return UserSnapshotBatch::validate($envelope, app(IdentityConfig::class));
    }

    public function test_snapshot_transport_uses_only_confidential_client_and_exact_subject_input(): void
    {
        Http::fake(['*' => Http::response($this->envelope())]);
        $batch = app(UserSnapshotClient::class)->read(['person']);
        $this->assertSame('person', $batch->profiles[0]->subject);
        Http::assertSent(fn ($request) => $request->url() === 'https://identity.test/api/consumer-sync/v1/profiles.read'
            && $request->hasHeader('Authorization', 'Basic '.base64_encode('web-1:secret')) && $request->data() === ['subjects' => ['person']]);
    }

    public function test_raw_subject_values_are_rejected_before_transport(): void
    {
        foreach ([[[], []], [new \stdClass, new \stdClass]] as $subjects) {
            try {
                app(UserSnapshotClient::class)->read($subjects);
                $this->fail('Malformed subject reached the provider');
            } catch (IdentityException $error) {
                $this->assertSame('user_sync_subjects_invalid', $error->errorCode);
            }
        }
        Http::assertNothingSent();
    }

    public static function badBindings(): array
    {
        return [['issuer', 'https://foreign.test/api/auth'], ['applicationId', 'foreign'], ['clientId', 'foreign'], ['policyVersion', 0], ['extra', true]];
    }

    #[DataProvider('badBindings')]
    public function test_foreign_or_malformed_snapshot_is_rejected(string $field, mixed $value): void
    {
        $data = $this->envelope();
        $data[$field] = $value;
        $this->expectException(IdentityException::class);
        $this->batch($data);
    }

    public function test_newer_owned_fields_map_to_existing_explicit_link_without_local_role_changes_and_unversioned_regression(): void
    {
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'Old name', 'email' => 'old@example.test']);
        $user = app(IdentityUserResolver::class)->resolve($projection);
        $repository = app(UserSnapshotRepository::class);
        $this->assertSame('applied', $repository->apply($this->batch($this->envelope())->profiles[0]));
        $this->assertSame('Current name', $user->refresh()->name);
        $this->assertSame('current@example.test', $user->email);
        $this->assertSame('https://images.example.test/avatar.png', $user->avatar_url);
        $this->assertNotNull($user->email_verified_at);
        $this->assertSame('local-reader', $user->local_role);
        app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'Delayed JIT', 'email' => 'delay@example.test']);
        $this->assertSame('Current name', app(IdentityUserResolver::class)->resolve($projection)->name);
        $this->assertSame('unchanged', $repository->apply($this->batch($this->envelope())->profiles[0]));
        $old = $this->envelope(1);
        $old['profiles'][0]['profile']['name'] = 'Stale';
        $this->assertSame('stale', $repository->apply($this->batch($old)->profiles[0]));
        $this->assertSame('Current name', $user->refresh()->name);
    }

    public function test_equal_version_different_facts_conflict_without_partial_mapping(): void
    {
        $repository = app(UserSnapshotRepository::class);
        $repository->apply($this->batch($this->envelope())->profiles[0]);
        $conflict = $this->envelope();
        $conflict['profiles'][0]['profile']['name'] = 'Conflicting';
        try {
            $repository->apply($this->batch($conflict)->profiles[0]);
            $this->fail('Equal-version conflict accepted');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_conflict', $error->errorCode);
        }
        $this->assertSame('Current name', SyncedNativeUser::firstOrFail()->name);
    }

    public function test_lifecycle_tombstone_retains_domain_user_retires_bound_sessions_and_requires_newer_reactivation(): void
    {
        $repository = app(UserSnapshotRepository::class);
        $repository->apply($this->batch($this->envelope())->profiles[0]);
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'person']);
        $user = SyncedNativeUser::firstOrFail();
        IdentitySession::create(['id' => 'bound', 'binding_hash' => app(IdentityConfig::class)->bindingHash(), 'subject' => 'person', 'sid' => 'central', 'token_vault' => 'fixture', 'selection' => [],
            'context_version' => 1, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        $repository->apply($this->batch($this->envelope(3, 'revoked'))->profiles[0]);
        $this->assertSame('revoked', $user->refresh()->identity_status);
        $this->assertNull($user->avatar_url);
        $this->assertSame('current@example.test', $user->email);
        $this->assertSame(0, IdentitySession::count());
        $this->assertSame(1, SyncedNativeUser::count());
        try {
            app(IdentityUserResolver::class)->resolve($projection);
            $this->fail('Inactive native user authenticated');
        } catch (IdentityException $error) {
            $this->assertSame('identity_user_inactive', $error->errorCode);
        }
        $this->assertSame('stale', $repository->apply($this->batch($this->envelope(2))->profiles[0]));
        $repository->apply($this->batch($this->envelope(4))->profiles[0]);
        $this->assertSame($user->id, app(IdentityUserResolver::class)->resolve($projection)->getAuthIdentifier());
    }

    public function test_binding_policy_fence_rejects_delayed_response_even_with_larger_subject_version(): void
    {
        $repository = app(UserSnapshotRepository::class);
        $repository->apply($this->batch($this->envelope(2, 'active', 3))->profiles[0]);
        $this->assertSame('stale', $repository->apply($this->batch($this->envelope(99, 'revoked', 2))->profiles[0]));
        $this->assertSame('active', SyncedNativeUser::firstOrFail()->identity_status);
    }

    public function test_custom_mapped_email_and_verification_columns_preserve_and_reset_their_own_address_proof(): void
    {
        Schema::create('custom_mapped_users', function (Blueprint $table): void {
            $table->id();
            $table->string('display_name');
            $table->string('contact_email');
            $table->timestamp('verified_on')->nullable();
            $table->timestamps();
        });
        $this->configure(['identity.consumers.one.users.model' => CustomMappedUser::class, 'identity.consumers.one.users.fields' => ['name' => 'display_name', 'email' => 'contact_email', 'email_verified_at' => 'verified_on'],
            'identity.consumers.one.users.factory' => FixtureNativeFactory::class]);
        FixtureNativeFactory::$create = fn ($projection) => CustomMappedUser::create(['display_name' => $projection->name, 'contact_email' => $projection->email]);
        $repository = app(UserSnapshotRepository::class);
        $repository->apply($this->batch($this->envelope())->profiles[0]);
        $user = CustomMappedUser::firstOrFail();
        $verified = $user->verified_on;
        $this->travel(60)->seconds();
        $repository->apply($this->batch($this->envelope(3))->profiles[0]);
        $this->assertSame($verified, $user->refresh()->verified_on);
        $changed = $this->envelope(4);
        $changed['profiles'][0]['profile']['email'] = 'new@example.test';
        $repository->apply($this->batch($changed)->profiles[0]);
        $this->assertSame('new@example.test', $user->refresh()->contact_email);
        $this->assertNotSame($verified, $user->verified_on);
    }

    public function test_batch_publishes_binding_policy_once_while_applying_each_subject(): void
    {
        $data = $this->envelope();
        $first = $data['profiles'][0];
        $data['profiles'] = [];
        for ($i = 0; $i < 100; $i++) {
            $entry = $first;
            $entry['subject'] = 'person-'.$i;
            $entry['profile']['email'] = 'person-'.$i.'@example.test';
            $data['profiles'][] = $entry;
        }
        $bindingReads = 0;
        $bindingUpdates = 0;
        DB::listen(function ($query) use (&$bindingReads, &$bindingUpdates): void {
            if (str_contains($query->sql, 'identity_user_sync_bindings')) {
                $bindingReads += str_starts_with($query->sql, 'select') ? 1 : 0;
                $bindingUpdates += str_starts_with($query->sql, 'update') ? 1 : 0;
            }
        });

        $this->assertSame(array_fill(0, 100, 'applied'), app(UserSnapshotRepository::class)->applyBatch($this->batch($data)));
        $this->assertSame(100, SyncedNativeUser::count());
        $this->assertSame(1, $bindingUpdates);
        $this->assertLessThanOrEqual(2, $bindingReads);
    }

    public function test_empty_newer_policy_batch_fences_delayed_nonempty_snapshot(): void
    {
        $repository = app(UserSnapshotRepository::class);
        $empty = $this->envelope(2, 'active', 7);
        $empty['profiles'] = [];
        $repository->applyBatch($this->batch($empty));
        $this->assertSame('stale', $repository->apply($this->batch($this->envelope(99, 'active', 6))->profiles[0]));
        $this->assertSame(0, SyncedNativeUser::count());
    }

    public static function invalidProfileFacts(): array
    {
        return [['picture', 'javascript:alert(1)'], ['picture', 'data:image/png;base64,AAAA'], ['picture', '/avatar.png'], ['picture', 'https://user:password@images.example.test/avatar.png'], ['emailVerified', 'true'], ['locale', 'fr'], ['name', []], ['email', 'not-an-email']];
    }

    #[DataProvider('invalidProfileFacts')]
    public function test_malformed_profile_facts_never_reach_mapping(string $field, mixed $value): void
    {
        $data = $this->envelope();
        $data['profiles'][0]['profile'][$field] = $value;
        $this->expectException(IdentityException::class);
        $this->batch($data);
    }

    public function test_sync_opt_in_is_required_before_transport(): void
    {
        $this->configure(['identity.consumers.one.sync.enabled' => false, 'identity.consumers.one.sync.provision_missing' => false]);
        try {
            app(UserSnapshotClient::class)->read(['person']);
            $this->fail('Disabled sync contacted provider');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_disabled', $error->errorCode);
        }
        Http::assertNothingSent();
    }

    public function test_large_sync_batch_has_its_own_bound_without_weakening_other_http_paths(): void
    {
        $data = $this->envelope();
        $entry = $data['profiles'][0];
        $entry['profile']['picture'] = 'https://images.example.test/'.str_repeat('a', 7900);
        $entry['profile']['bio'] = str_repeat('b', 2000);
        $entry['profile']['adminNotes'] = str_repeat('n', 5000);
        $entry['profile']['socialLinks'] = [];
        for ($link = 0; $link < 20; $link++) {
            $entry['profile']['socialLinks']['site-'.$link] = 'https://social.example.test/'.str_repeat('s', 2000);
        }
        $data['profiles'] = [];
        for ($i = 0; $i < 100; $i++) {
            $entry['subject'] = 'person-'.$i;
            $data['profiles'][] = $entry;
        }
        Http::fake(['*' => Http::response($data)]);
        $this->assertCount(100, app(UserSnapshotClient::class)->read(array_column($data['profiles'], 'subject'))->profiles);
        try {
            app(IdentityHttp::class)->get('/api/ordinary');
            $this->fail('Ordinary response bound was weakened');
        } catch (IdentityException $error) {
            $this->assertSame('response_too_large', $error->errorCode);
        }
    }

    public function test_duplicate_email_conflict_cannot_link_existing_user_or_partially_publish_version(): void
    {
        Schema::table('synced_native_users', fn (Blueprint $table) => $table->unique('email'));
        SyncedNativeUser::create(['name' => 'Existing other user', 'email' => 'current@example.test']);
        try {
            app(UserSnapshotRepository::class)->apply($this->batch($this->envelope())->profiles[0]);
            $this->fail('Duplicate address was linked');
        } catch (IdentityException $error) {
            $this->assertSame('identity_user_conflict', $error->errorCode);
        }
        $this->assertSame(1, SyncedNativeUser::count());
        $this->assertDatabaseCount('identity_user_links', 0);
        $this->assertDatabaseCount('identity_user_sync_states', 0);
    }

    public function test_existing_association_resolution_is_read_only_without_projection_transaction(): void
    {
        app(UserSnapshotRepository::class)->apply($this->batch($this->envelope())->profiles[0]);
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'person']);
        $levels = [];
        $writes = [];
        DB::listen(function ($query) use (&$levels, &$writes): void {
            $levels[] = $query->connection->transactionLevel();
            if (preg_match('/^(update|insert|delete)/i', $query->sql)) {
                $writes[] = $query->sql;
            }
        });
        $resolver = app(IdentityUserResolver::class);
        $first = $resolver->resolve($projection);
        $second = $resolver->resolve($projection);
        $this->assertSame($first->id, $second->id);
        $this->assertSame([], $writes);
        $this->assertSame([0], array_values(array_unique($levels)));
    }

    public function test_existing_native_row_is_locked_before_projection_during_snapshot_mapping(): void
    {
        app(UserSnapshotRepository::class)->apply($this->batch($this->envelope())->profiles[0]);
        $order = [];
        $this->graph()->instance(UserProjectionRepository::class, new class(function ($step) use (&$order) {
            $order[] = $step;
        }) extends UserProjectionRepository {

            public function __construct(private \Closure $record)
            {
                parent::__construct(app(IdentityConfig::class), app(ConsumerGraph::class)->make(ProjectionOwnership::class));
            }

            public function synchronize(string $issuer, string $subject, array $profile): array
            {
                ($this->record)('projection');

                return parent::synchronize($issuer, $subject, $profile);
            }
        });
        $this->graph()->instance(NativeUserRepository::class, new class(app(IdentityConfig::class), function ($step) use (&$order) {
            $order[] = $step;
        }) extends NativeUserRepository {

            public function __construct(IdentityConfig $config, private \Closure $record)
            {
                parent::__construct($config);
            }

            public function linked(IdentityUser $projection, bool $lock = true): ?Authenticatable
            {
                if ($lock) {
                    ($this->record)('native');
                }

                return parent::linked($projection, $lock);
            }
        });
        app(UserSnapshotRepository::class)->apply($this->batch($this->envelope(3, 'suspended'))->profiles[0]);
        $this->assertSame(['projection', 'native', 'projection'], $order);
    }

    public static function provisioningOptions(): array
    {
        return ['provision enabled' => [true], 'provision disabled' => [false]];
    }

    #[DataProvider('provisioningOptions')]
    public function test_signed_never_visited_subject_refetches_and_only_provisions_with_explicit_flag(bool $provision): void
    {
        $this->configure(['identity.consumers.one.sync.provision_missing' => $provision]);
        Queue::fake();
        $body = json_encode(['schema_version' => 1, 'event_id' => 'new-person', 'type' => 'grant.updated', 'application_id' => 'app-1', 'occurred_at' => gmdate('Y-m-d\TH:i:s\Z'), 'subject' => 'person']);
        $timestamp = (string) time();
        app(CallbackReceiver::class)->event($body, ['x-identity-event-id' => 'new-person', 'x-identity-timestamp' => $timestamp, 'x-identity-signature' => 'v1='.hash_hmac('sha256', 'new-person.'.$timestamp.'.'.$body, str_repeat('e', 32))]);
        Queue::assertPushed(RefreshIdentityUser::class, 1);
        Http::fake(['*' => Http::response($this->envelope())]);
        $request = UserSyncRequest::firstOrFail();
        app(UserSyncManager::class)->process($request->id);
        $this->assertSame($provision ? 1 : 0, SyncedNativeUser::count());
        $this->assertDatabaseCount('identity_users', 1);
    }

    public function test_signed_omitted_subject_does_not_block_returned_known_profile_or_new_directory_person(): void
    {
        Queue::fake();
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'b-known', 'name' => 'Before', 'email' => 'known@example.test']);
        $known = app(IdentityUserResolver::class)->resolve($projection);
        $body = json_encode(['schema_version' => 1, 'event_id' => 'contact-event', 'type' => 'grant.updated', 'application_id' => 'app-1', 'occurred_at' => gmdate('Y-m-d\TH:i:s\Z'), 'subject' => 'a-contact']);
        $timestamp = (string) time();
        app(CallbackReceiver::class)->event($body, ['x-identity-event-id' => 'contact-event', 'x-identity-timestamp' => $timestamp, 'x-identity-signature' => 'v1='.hash_hmac('sha256', 'contact-event.'.$timestamp.'.'.$body, str_repeat('e', 32))]);
        Queue::assertPushed(RefreshIdentityUser::class, 1);
        $updated = $this->envelope()['profiles'][0];
        $updated['subject'] = 'b-known';
        $updated['profile']['email'] = 'known@example.test';
        $new = $updated;
        $new['subject'] = 'c-new';
        $new['profile']['email'] = 'new@example.test';
        Http::fake(function ($request) use ($updated, $new) {
            $data = $this->envelope();
            $data['profiles'] = str_ends_with($request->url(), 'profiles.list') ? [$new] : (in_array('b-known', $request['subjects'], true) ? [$updated] : []);

            return Http::response($data);
        });

        $manager = app(UserSyncManager::class);
        $result = $manager->reconcile(100);

        $this->assertSame(1, $result['missing']);
        $this->assertFalse($result['completed']);
        $this->assertSame('Current name', $known->refresh()->name);
        $this->assertSame(2, SyncedNativeUser::count());
        $this->assertSame(2, IdentityUser::count());
        $this->assertDatabaseMissing('identity_users', ['subject' => 'a-contact']);
        $missing = UserSyncRequest::where('subject', 'a-contact')->firstOrFail();
        $this->assertSame('user_sync_subject_missing', $missing->last_error);
        $this->assertLessThan($missing->generation, $missing->completed_generation);
        $returned = UserSyncRequest::where('subject', 'b-known')->firstOrFail();
        $this->assertSame($returned->generation, $returned->completed_generation);
        try {
            $manager->process($missing->id);
            $this->fail('Individual omitted subject was treated as completed');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_subject_missing', $error->errorCode);
        }
        $this->assertSame(2, SyncedNativeUser::count());
    }

    public function test_omission_allows_bounded_known_and_list_cursor_progress_across_runs(): void
    {
        Queue::fake();
        $manager = app(UserSyncManager::class);
        $manager->request('a-contact');
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'z-known', 'name' => 'Before', 'email' => 'known@example.test']);
        $known = app(IdentityUserResolver::class)->resolve($projection);
        $entry = $this->envelope()['profiles'][0];
        $entry['subject'] = 'z-known';
        $entry['profile']['email'] = 'known@example.test';
        $new = $entry;
        $new['subject'] = '0-new';
        $new['profile']['email'] = 'new@example.test';
        $cursor = 'v1.'.str_repeat('A', 300);
        Http::fake(function ($request) use ($entry, $new, $cursor) {
            $data = $this->envelope();
            if (str_ends_with($request->url(), 'profiles.read')) {
                $data['profiles'] = in_array('z-known', $request['subjects'], true) ? [$entry] : [];
            } elseif (isset($request['cursor'])) {
                $data['profiles'] = [$entry];
            } else {
                $data['profiles'] = [$new];
                $data['nextCursor'] = $cursor;
            }

            return Http::response($data);
        });
        $first = $manager->reconcile(1);
        $this->assertSame(1, $first['missing']);
        $this->assertSame('a-contact', $first['knownCursor']);
        $this->assertSame($cursor, $first['nextCursor']);
        $this->assertSame('Before', $known->refresh()->name);
        $this->assertSame(2, SyncedNativeUser::count());

        $second = $manager->reconcile(1);
        $this->assertSame(0, $second['missing']);
        $this->assertNull($second['knownCursor']);
        $this->assertNull($second['nextCursor']);
        $this->assertSame('Current name', $known->refresh()->name);
        $this->assertFalse($second['completed']);
        $this->assertSame(1, $second['pending']);
        $this->assertDatabaseMissing('identity_users', ['subject' => 'a-contact']);
        $requests = Http::recorded(fn ($request) => str_ends_with($request->url(), 'profiles.list'))->values();
        $this->assertSame($cursor, $requests[1][0]['cursor']);
    }
}
