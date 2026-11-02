<?php

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Models\IdentityUserLink;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserImportBootstrap;
use IdentityPlatform\Laravel\Sync\UserImportClient;
use IdentityPlatform\Laravel\Sync\UserImportResult;
use IdentityPlatform\Laravel\Sync\UserSnapshot;
use IdentityPlatform\Laravel\Sync\UserSnapshotRepository;
use IdentityPlatform\Laravel\Sync\UserSyncState;
use IdentityPlatform\Laravel\Tests\TestCase;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

class ImportNativeUser extends User
{
    protected $guarded = [];
}

class UserImportTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('import_native_users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email');
            $table->string('local_role')->default('host-admin');
            $table->string('password')->default('host-credential');
            $table->timestamps();
        });
        $this->configure(['identity.consumers.one.sync.enabled' => true, 'identity.consumers.one.sync.import_enabled' => true, 'identity.consumers.one.users.model' => ImportNativeUser::class, 'identity.consumers.one.users.fields' => ['name' => 'name', 'email' => 'email']]);
        Http::preventStrayRequests();
    }

    private function envelope(array $mappings = []): array
    {
        return ['contract' => 'platform-consumer-sync-import.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1,
            'mappings' => $mappings ?: [['sourceUserId' => 'native-42', 'subject' => 'provider-generated', 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile()]]];
    }

    private function importResult(?array $data = null, array $sources = ['native-42']): UserImportResult
    {
        return UserImportResult::validate($data ?? $this->envelope(), app(IdentityConfig::class), $sources);
    }

    public function test_import_transport_returns_typed_bound_mapping_without_sending_actor_credentials(): void
    {
        $users = [['sourceUserId' => 'native-42', 'name' => 'Native', 'email' => 'current@example.test', 'emailVerified' => true, 'passwordHash' => '$2y$10$'.str_repeat('a', 53), 'roleKeys' => ['reader']]];
        Http::fake(['*' => Http::response($this->envelope())]);
        $result = app(UserImportClient::class)->import($users);
        $this->assertSame('native-42', $result->mappings[0]->sourceUserId);
        $this->assertSame('provider-generated', $result->mappings[0]->snapshot->subject);
        Http::assertSent(fn ($request) => $request->url() === 'https://identity.test/api/consumer-sync/v1/profiles.import'
            && $request->hasHeader('Authorization', 'Basic '.base64_encode('web-1:secret')) && $request->data() === ['users' => $users]);
    }

    public static function invalidBindings(): array
    {
        return [['contract', 'platform-consumer-sync.v1'], ['issuer', 'https://foreign.test/api/auth'], ['applicationId', 'foreign'], ['clientId', 'foreign'], ['policyVersion', 0], ['extra', true]];
    }

    #[DataProvider('invalidBindings')]
    public function test_import_result_rejects_foreign_or_unexpected_binding(string $field, mixed $value): void
    {
        $data = $this->envelope();
        $data[$field] = $value;
        $this->expectException(IdentityException::class);
        $this->importResult($data);
    }

    public function test_import_result_requires_exact_requested_sources_and_distinct_subjects(): void
    {
        $mapping = $this->envelope()['mappings'][0];
        $other = [...$mapping, 'sourceUserId' => 'another'];
        $this->expectException(IdentityException::class);
        $this->importResult($this->envelope([$mapping, $other]), ['native-42', 'another']);
    }

    public function test_import_result_cannot_omit_requested_source(): void
    {
        $this->expectException(IdentityException::class);
        $this->importResult(null, ['native-42', 'omitted']);
    }

    public function test_import_result_cannot_add_unrequested_source(): void
    {
        $this->expectException(IdentityException::class);
        $this->importResult(null, ['other']);
    }

    public function test_import_result_accepts_tombstone_mapping_without_profile(): void
    {
        $data = $this->envelope();
        $data['mappings'][0]['state'] = 'deleted';
        $data['mappings'][0]['profile'] = null;
        $this->assertNull($this->importResult($data)->mappings[0]->snapshot->profile);
    }

    public function test_import_requires_both_local_opt_ins_before_transport(): void
    {
        foreach (['identity.consumers.one.sync.enabled', 'identity.consumers.one.sync.import_enabled'] as $key) {
            $this->configure([$key => false, 'identity.consumers.one.sync.import_enabled' => false]);
            try {
                app(UserImportClient::class)->import([['sourceUserId' => 'native-42', 'name' => 'Name', 'email' => 'current@example.test', 'emailVerified' => true]]);
                $this->fail('Disabled import contacted provider');
            } catch (IdentityException $error) {
                $this->assertSame('user_import_disabled', $error->errorCode);
            }
            $this->configure([$key => true, 'identity.consumers.one.sync.import_enabled' => true]);
        }
        Http::assertNothingSent();
    }

    public static function invalidInputs(): array
    {
        $user = ['sourceUserId' => 'native-42', 'name' => 'Name', 'email' => 'current@example.test', 'emailVerified' => true];

        return [[[]], [array_fill(0, 101, $user)], [[$user, $user]], [[$user, [...$user, 'sourceUserId' => 'second', 'email' => 'CURRENT@example.test']]], [[array_replace($user, ['sourceUserId' => ''])]], [[array_replace($user, ['email' => 'invalid'])]], [[array_replace($user, ['active' => null])]], [[array_replace($user, ['roleKeys' => null])]], [[array_replace($user, ['profileCompleted' => true])]]];
    }

    #[DataProvider('invalidInputs')]
    public function test_invalid_import_input_is_rejected_without_transport(array $users): void
    {
        try {
            app(UserImportClient::class)->import($users);
            $this->fail('Invalid import accepted');
        } catch (IdentityException $error) {
            $this->assertSame('user_import_input_invalid', $error->errorCode);
        }
        Http::assertNothingSent();
    }

    public function test_bootstrap_associates_supplied_native_id_ignoring_email_and_preserving_host_fields(): void
    {
        $emailMatch = ImportNativeUser::create(['name' => 'Email match', 'email' => 'current@example.test']);
        $target = ImportNativeUser::create(['name' => 'Exact native', 'email' => 'different@example.test']);
        $bootstrap = app(UserImportBootstrap::class);
        $associations = [['sourceUserId' => 'native-42', 'nativeUserId' => $target->id]];
        $this->assertSame(['applied'], $bootstrap->associate($this->importResult(), $associations));
        $projection = IdentityUser::firstOrFail();
        $this->assertSame($target->id, app(IdentityUserResolver::class)->resolve($projection)->id);
        $this->assertSame('current@example.test', $target->refresh()->email);
        $this->assertSame('Email match', $emailMatch->refresh()->name);
        $this->assertSame('host-admin', $target->local_role);
        $this->assertSame('host-credential', $target->password);
        $this->assertSame(['unchanged'], $bootstrap->associate($this->importResult(), $associations));
        $this->assertSame(2, ImportNativeUser::count());
        $this->assertSame(1, IdentityUserLink::count());
    }

    public function test_bootstrap_replay_cannot_regress_newer_lifecycle_or_profile(): void
    {
        $target = ImportNativeUser::create(['name' => 'Native', 'email' => 'different@example.test']);
        $result = $this->importResult();
        $associations = [['sourceUserId' => 'native-42', 'nativeUserId' => $target->id]];
        $bootstrap = app(UserImportBootstrap::class);
        $bootstrap->associate($result, $associations);
        app(UserSnapshotRepository::class)->apply(UserSnapshot::validate(['subject' => 'provider-generated', 'version' => 2, 'state' => 'revoked', 'profile' => null], 1, app(IdentityConfig::class)));
        $this->assertSame(['stale'], $bootstrap->associate($result, $associations));
        $this->assertSame('revoked', UserSyncState::firstOrFail()->state);
        $this->expectExceptionObject(new IdentityException('identity_user_inactive', 403));
        app(IdentityUserResolver::class)->resolve(IdentityUser::firstOrFail());
    }

    public function test_bootstrap_cannot_reassign_existing_source_to_another_native_user(): void
    {
        $first = ImportNativeUser::create(['name' => 'First', 'email' => 'one@example.test']);
        $second = ImportNativeUser::create(['name' => 'Second', 'email' => 'two@example.test']);
        $bootstrap = app(UserImportBootstrap::class);
        $bootstrap->associate($this->importResult(), [['sourceUserId' => 'native-42', 'nativeUserId' => $first->id]]);
        $this->expectExceptionObject(new IdentityException('user_import_association_conflict', 409));
        $bootstrap->associate($this->importResult(), [['sourceUserId' => 'native-42', 'nativeUserId' => $second->id]]);
    }

    public function test_bootstrap_cannot_reassign_existing_source_to_another_subject(): void
    {
        $target = ImportNativeUser::create(['name' => 'Native', 'email' => 'one@example.test']);
        $bootstrap = app(UserImportBootstrap::class);
        $associations = [['sourceUserId' => 'native-42', 'nativeUserId' => $target->id]];
        $bootstrap->associate($this->importResult(), $associations);
        $data = $this->envelope();
        $data['mappings'][0]['subject'] = 'different-provider-subject';
        $this->expectExceptionObject(new IdentityException('user_import_association_conflict', 409));
        $bootstrap->associate($this->importResult($data), $associations);
    }

    public function test_bootstrap_checks_current_binding_before_local_writes(): void
    {
        $result = $this->importResult();
        $target = ImportNativeUser::create(['name' => 'Native', 'email' => 'one@example.test']);
        $this->configure(['identity.consumers.one.browser.client_id' => 'different-client']);
        try {
            app(UserImportBootstrap::class)->associate($result, [['sourceUserId' => 'native-42', 'nativeUserId' => $target->id]]);
            $this->fail('Foreign result associated');
        } catch (IdentityException $error) {
            $this->assertSame('user_import_binding_changed', $error->errorCode);
        }
        $this->assertSame(0, IdentityUserLink::count());
    }

    public function test_bootstrap_missing_native_id_rolls_back_the_entire_batch(): void
    {
        $target = ImportNativeUser::create(['name' => 'Native', 'email' => 'one@example.test']);
        $first = $this->envelope()['mappings'][0];
        $second = [...$first, 'sourceUserId' => 'second', 'subject' => 'second-subject'];
        try {
            app(UserImportBootstrap::class)->associate($this->importResult($this->envelope([$first, $second]), ['native-42', 'second']), [
                ['sourceUserId' => 'native-42', 'nativeUserId' => $target->id], ['sourceUserId' => 'second', 'nativeUserId' => 999],
            ]);
            $this->fail('Missing native ID accepted');
        } catch (IdentityException $error) {
            $this->assertSame('user_import_association_invalid', $error->errorCode);
        }
        $this->assertSame(0, IdentityUser::count());
        $this->assertSame(0, IdentityUserLink::count());
        $this->assertSame(0, UserSyncState::count());
        $this->assertSame('Native', $target->refresh()->name);
    }

    public function test_bootstrap_conflict_after_first_mapping_rolls_back_profiles_links_and_source_mappings(): void
    {
        $firstUser = ImportNativeUser::create(['name' => 'First native', 'email' => 'one@example.test']);
        $secondUser = ImportNativeUser::create(['name' => 'Second native', 'email' => 'two@example.test']);
        $bootstrap = app(UserImportBootstrap::class);
        $occupied = $this->envelope();
        $occupied['mappings'][0]['sourceUserId'] = 'occupied';
        $occupied['mappings'][0]['subject'] = 'occupied-subject';
        $bootstrap->associate($this->importResult($occupied, ['occupied']), [['sourceUserId' => 'occupied', 'nativeUserId' => $secondUser->id]]);
        $first = $this->envelope()['mappings'][0];
        $second = [...$first, 'sourceUserId' => 'second', 'subject' => 'second-subject'];
        try {
            $bootstrap->associate($this->importResult($this->envelope([$first, $second]), ['native-42', 'second']), [
                ['sourceUserId' => 'native-42', 'nativeUserId' => $firstUser->id], ['sourceUserId' => 'second', 'nativeUserId' => $secondUser->id],
            ]);
            $this->fail('Existing native association reassigned');
        } catch (IdentityException $error) {
            $this->assertSame('user_import_association_conflict', $error->errorCode);
        }
        $this->assertSame('First native', $firstUser->refresh()->name);
        $this->assertSame(1, IdentityUser::count());
        $this->assertSame(1, IdentityUserLink::count());
        $this->assertSame(1, UserSyncState::count());
        $this->assertDatabaseCount('identity_user_import_links', 1);
    }

    public function test_bootstrap_rejects_duplicate_native_owner(): void
    {
        $target = ImportNativeUser::create(['name' => 'Native', 'email' => 'one@example.test']);
        $first = $this->envelope()['mappings'][0];
        $second = [...$first, 'sourceUserId' => 'second', 'subject' => 'second-subject'];
        $this->expectExceptionObject(new IdentityException('user_import_association_invalid', 422));
        app(UserImportBootstrap::class)->associate($this->importResult($this->envelope([$first, $second]), ['native-42', 'second']), [
            ['sourceUserId' => 'native-42', 'nativeUserId' => $target->id], ['sourceUserId' => 'second', 'nativeUserId' => $target->id],
        ]);
    }

    public function test_bootstrap_native_identifier_is_exact(): void
    {
        $target = ImportNativeUser::create(['name' => 'Native', 'email' => 'one@example.test']);
        $this->expectExceptionObject(new IdentityException('user_import_association_invalid', 409));
        app(UserImportBootstrap::class)->associate($this->importResult(), [['sourceUserId' => 'native-42', 'nativeUserId' => '0'.$target->id]]);
    }

    public function test_bootstrap_rejects_delayed_result_with_older_binding_policy(): void
    {
        $target = ImportNativeUser::create(['name' => 'Native', 'email' => 'one@example.test']);
        app(UserSnapshotRepository::class)->apply(UserSnapshot::validate(['subject' => 'other', 'version' => 1, 'state' => 'revoked', 'profile' => null], 2, app(IdentityConfig::class)));
        try {
            app(UserImportBootstrap::class)->associate($this->importResult(), [['sourceUserId' => 'native-42', 'nativeUserId' => $target->id]]);
            $this->fail('Older policy accepted');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_policy_stale', $error->errorCode);
        }
        $this->assertSame(0, IdentityUserLink::count());
        $this->assertDatabaseCount('identity_user_import_links', 0);
    }

    public function test_bootstrap_new_association_uses_current_profile_when_import_response_is_stale(): void
    {
        $target = ImportNativeUser::create(['name' => 'Native', 'email' => 'one@example.test']);
        app(UserSnapshotRepository::class)->apply(UserSnapshot::validate(['subject' => 'provider-generated', 'version' => 2, 'state' => 'active', 'profile' => ProfileFixture::profile(['name' => 'Newer name'])], 1, app(IdentityConfig::class)));
        $this->assertSame(['stale'], app(UserImportBootstrap::class)->associate($this->importResult(), [['sourceUserId' => 'native-42', 'nativeUserId' => $target->id]]));
        $this->assertSame('Newer name', $target->refresh()->name);
        $this->assertSame(2, UserSyncState::firstOrFail()->version);
    }

    public function test_bootstrap_rejects_duplicate_native_owner_and_unknown_source_before_writes(): void
    {
        $target = ImportNativeUser::create(['name' => 'Native', 'email' => 'one@example.test']);
        $this->expectExceptionObject(new IdentityException('user_import_association_invalid', 422));
        app(UserImportBootstrap::class)->associate($this->importResult(), [['sourceUserId' => 'other-source', 'nativeUserId' => $target->id]]);
    }
}
