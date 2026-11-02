<?php

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserImportBootstrap;
use IdentityPlatform\Laravel\Sync\UserImportResult;
use IdentityPlatform\Laravel\Sync\UserSnapshot;
use IdentityPlatform\Laravel\Sync\UserSnapshotBatch;
use IdentityPlatform\Laravel\Sync\UserSnapshotRepository;
use IdentityPlatform\Laravel\Sync\UserSyncManager;
use IdentityPlatform\Laravel\Sync\UserSyncState;
use IdentityPlatform\Laravel\Sync\UserSyncWorkRepository;
use IdentityPlatform\Laravel\Tests\TestCase;
use IdentityPlatform\Laravel\Users\EloquentNativeUserMapper;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;

class ProjectionNativeUser extends User
{
    protected $table = 'projection_native_users';

    protected $guarded = [];

    use SoftDeletes;
}
class FailingProjectionMapper extends EloquentNativeUserMapper
{
    public static bool $fail = false;

    public static ?string $failSubject = null;

    public function synchronize(Authenticatable $user, IdentityUser $projection): void
    {
        if (self::$fail && (self::$failSubject === null || self::$failSubject === $projection->subject)) {
            throw new \RuntimeException('Private display transform detail');
        } parent::synchronize($user, $projection);
    }
}
class NativeProjectionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        FailingProjectionMapper::$fail = false;
        FailingProjectionMapper::$failSubject = null;
        Schema::create('projection_native_users', function (Blueprint $t): void {
            $t->id();
            $t->string('name');
            $t->string('email');
            $t->string('local_data')->default('retained');
            $t->timestamps();
            $t->softDeletes();
        });
        $this->configure(['identity.consumers.one.sync.enabled' => true, 'identity.consumers.one.sync.provision_missing' => true, 'identity.consumers.one.users.model' => ProjectionNativeUser::class, 'identity.consumers.one.users.fields' => ['name' => 'name', 'email' => 'email'], 'identity.consumers.one.users.mapper' => FailingProjectionMapper::class]);
    }

    private function snapshot(int $version, string $state = 'active'): UserSnapshot
    {
        return UserSnapshot::validate(['subject' => 'person', 'version' => $version, 'state' => $state, 'profile' => in_array($state, ['revoked', 'deleted']) ? null : ProfileFixture::profile()], 1, app(IdentityConfig::class));
    }

    public function test_inactive_acceptance_and_retirement_survive_mapper_failure_and_same_version_retries(): void
    {
        $repo = app(UserSnapshotRepository::class);
        $repo->apply($this->snapshot(1));
        IdentitySession::create(['id' => 'bound', 'binding_hash' => app(IdentityConfig::class)->bindingHash(), 'subject' => 'person', 'sid' => 'central', 'token_vault' => 'fixture', 'selection' => [], 'context_version' => 1, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
        FailingProjectionMapper::$fail = true;
        $this->assertSame('native_pending', $repo->apply($this->snapshot(2, 'suspended')));
        $state = UserSyncState::firstOrFail();
        $this->assertSame(2, $state->version);
        $this->assertSame(1, $state->native_version);
        $this->assertSame('pending', $state->native_status);
        $this->assertSame('native_projection_failed', $state->native_error);
        $this->assertSame(0, IdentitySession::count());
        try {
            app(IdentityUserResolver::class)->resolve(IdentityUser::firstOrFail());
            $this->fail('Inactive resolved');
        } catch (IdentityException $e) {
            $this->assertSame('identity_user_inactive', $e->errorCode);
        }
        FailingProjectionMapper::$fail = false;
        $this->assertSame('applied', $repo->apply($this->snapshot(2, 'suspended')));
        $this->assertSame(2, $state->refresh()->native_version);
        $this->assertSame('applied', $state->native_status);
        $this->assertSame('retained', ProjectionNativeUser::firstOrFail()->local_data);
    }

    public function test_missing_native_row_does_not_prevent_revocation_and_old_active_retry_is_stale(): void
    {
        $repo = app(UserSnapshotRepository::class);
        $repo->apply($this->snapshot(1));
        DB::table('projection_native_users')->delete();
        $this->assertSame('native_pending', $repo->apply($this->snapshot(3, 'revoked')));
        $this->assertSame('revoked', UserSyncState::firstOrFail()->state);
        $this->assertSame('stale', $repo->apply($this->snapshot(2)));
        $this->assertSame(0, ProjectionNativeUser::count());
    }

    public function test_inactive_caller_owned_outer_transaction_is_refused(): void
    {
        $this->expectExceptionObject(new IdentityException('user_sync_outer_transaction_unsupported', 409));
        DB::transaction(fn () => app(UserSnapshotRepository::class)->apply($this->snapshot(1, 'revoked')));
    }

    public function test_soft_deleted_native_row_is_retained_and_does_not_block_inactive_security(): void
    {
        $repo = app(UserSnapshotRepository::class);
        $repo->apply($this->snapshot(1));
        $native = ProjectionNativeUser::firstOrFail();
        $native->delete();
        $this->assertSame('native_pending', $repo->apply($this->snapshot(2, 'deleted')));
        $this->assertSame('deleted', UserSyncState::firstOrFail()->state);
        $this->assertSame(1, ProjectionNativeUser::withTrashed()->count());
        $this->assertSame(0, ProjectionNativeUser::count());
    }

    public function test_all_inactive_lifecycle_states_deny_resolution(): void
    {
        $repo = app(UserSnapshotRepository::class);
        $version = 1;
        $repo->apply($this->snapshot($version++));
        foreach (['pending', 'suspended', 'revoked', 'deleted'] as $state) {
            $this->assertSame('applied', $repo->apply($this->snapshot($version++, $state)));
            try {
                app(IdentityUserResolver::class)->resolve(IdentityUser::firstOrFail());
                $this->fail('Inactive resolved');
            } catch (IdentityException $error) {
                $this->assertSame('identity_user_inactive', $error->errorCode);
            }
        }
    }

    public function test_native_pending_keeps_work_generation_incomplete_and_reconcile_incomplete(): void
    {
        $repo = app(UserSnapshotRepository::class);
        $repo->apply($this->snapshot(1));
        FailingProjectionMapper::$fail = true;
        $wire = ['contract' => 'platform-consumer-sync.v1', 'issuer' => app(IdentityConfig::class)->issuer(), 'applicationId' => app(IdentityConfig::class)->applicationId(), 'clientId' => app(IdentityConfig::class)->clientId(), 'policyVersion' => 1, 'profiles' => [['subject' => 'person', 'version' => 2, 'state' => 'suspended', 'profile' => ProfileFixture::profile()]], 'nextCursor' => null];
        Http::fake(['*' => Http::response($wire)]);
        $work = app(UserSyncWorkRepository::class);
        $request = $work->request('person');
        try {
            app(UserSyncManager::class)->process($request->id);
            $this->fail('Pending completed');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_native_pending', $error->errorCode);
        }
        $this->assertLessThan($request->generation, $request->refresh()->completed_generation);
        $result = app(UserSyncManager::class)->reconcile();
        $this->assertFalse($result['completed']);
        $this->assertSame(1, $result['nativePending']);
        $this->assertSame(1, $result['pending']);
        FailingProjectionMapper::$fail = false;
        app(UserSyncManager::class)->process($request->id);
        $this->assertSame($request->generation, $request->refresh()->completed_generation);
    }

    public function test_inactive_import_association_failure_cannot_roll_back_accepted_security(): void
    {
        $repo = app(UserSnapshotRepository::class);
        $repo->apply($this->snapshot(1));
        $wire = ['contract' => 'platform-consumer-sync-import.v1', 'issuer' => app(IdentityConfig::class)->issuer(), 'applicationId' => app(IdentityConfig::class)->applicationId(), 'clientId' => app(IdentityConfig::class)->clientId(), 'policyVersion' => 1, 'mappings' => [['sourceUserId' => 'source', 'subject' => 'person', 'version' => 2, 'state' => 'revoked', 'profile' => null]]];
        $result = UserImportResult::validate($wire, app(IdentityConfig::class), ['source']);
        try {
            app(UserImportBootstrap::class)->associate($result, [['sourceUserId' => 'source', 'nativeUserId' => 999]]);
            $this->fail('Missing import row accepted');
        } catch (IdentityException $e) {
            $this->assertSame('user_import_association_invalid', $e->errorCode);
        }
        $this->assertSame('revoked', UserSyncState::firstOrFail()->state);
        $this->assertSame(2, UserSyncState::firstOrFail()->version);
        $this->assertSame(1, app(UserSyncWorkRepository::class)->pendingCount());
    }

    public function test_native_batch_rolls_back_while_both_inactive_acceptances_remain_durable(): void
    {
        $config = app(IdentityConfig::class);
        $repo = app(UserSnapshotRepository::class);
        $profiles = [];
        foreach (['person', 'second'] as $subject) {
            $record = ['subject' => $subject, 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile(['name' => 'Old '.$subject])];
            $repo->apply(UserSnapshot::validate($record, 1, $config));
            $record['version'] = 2;
            $record['state'] = 'suspended';
            $record['profile']['name'] = 'New '.$subject;
            $profiles[] = $record;
        }
        $wire = ['contract' => 'platform-consumer-sync.v1', 'issuer' => $config->issuer(), 'applicationId' => $config->applicationId(), 'clientId' => $config->clientId(), 'policyVersion' => 1, 'profiles' => $profiles, 'nextCursor' => null];
        FailingProjectionMapper::$fail = true;
        FailingProjectionMapper::$failSubject = 'second';
        $this->assertSame(['native_pending', 'native_pending'], $repo->applyBatch(UserSnapshotBatch::validate($wire, $config)));
        $this->assertSame(['Old person', 'Old second'], ProjectionNativeUser::orderBy('id')->pluck('name')->all());
        $this->assertSame([2, 2], UserSyncState::orderBy('subject')->pluck('version')->all());
        $this->assertSame([1, 1], UserSyncState::orderBy('subject')->pluck('native_version')->all());
        FailingProjectionMapper::$fail = false;
        $this->assertSame(['applied', 'applied'], $repo->applyBatch(UserSnapshotBatch::validate($wire, $config)));
        $this->assertSame('New person', IdentityUser::where('subject', 'person')->firstOrFail()->name);
    }

    public function test_equal_revision_refreshes_policy_while_native_projection_stays_pending(): void
    {
        $repository = app(UserSnapshotRepository::class);
        $repository->apply($this->snapshot(1));
        FailingProjectionMapper::$fail = true;
        FailingProjectionMapper::$failSubject = 'person';
        $this->assertSame('native_pending', $repository->apply($this->snapshot(2, 'suspended')));
        $state = UserSyncState::where('subject', 'person')->firstOrFail();
        $accepted = $state->only(['version', 'digest', 'profile', 'state', 'native_version']);
        $configuration = app(IdentityConfig::class);
        $repository->apply(UserSnapshot::validate(['subject' => 'other-person', 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile()], 2, $configuration));
        $fresh = UserSnapshot::validate(['subject' => 'person', 'version' => 2, 'state' => 'suspended', 'profile' => $state->profile], 2, $configuration);
        $this->assertSame('native_pending', $repository->apply($fresh));
        $this->assertSame(2, $state->refresh()->policy_version);
        $this->assertSame($accepted, $state->only(['version', 'digest', 'profile', 'state', 'native_version']));
        $this->assertSame('pending', $state->native_status);
        $this->assertSame('stale', $repository->apply($this->snapshot(2, 'suspended')));
        FailingProjectionMapper::$fail = false;
        $this->assertSame('applied', $repository->apply($fresh));
        $this->assertSame(2, $state->refresh()->native_version);
    }

    public function test_active_pending_policy_evidence_survives_failed_native_only_retry(): void
    {
        $repository = app(UserSnapshotRepository::class);
        $repository->apply($this->snapshot(4));
        $state = UserSyncState::where('subject', 'person')->firstOrFail();
        // Existing accepted active projection awaiting replay after package migration.
        $state->update(['native_status' => 'pending', 'native_version' => 0]);
        $accepted = $state->only(['version', 'digest', 'profile', 'state', 'native_version']);
        $configuration = app(IdentityConfig::class);
        $repository->apply(UserSnapshot::validate(['subject' => 'other-person', 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile()], 2, $configuration));
        FailingProjectionMapper::$fail = true;
        FailingProjectionMapper::$failSubject = 'person';
        $fresh = UserSnapshot::validate(['subject' => 'person', 'version' => 4, 'state' => 'active', 'profile' => $state->profile], 2, $configuration);
        try {
            $repository->apply($fresh);
            $this->fail('Mapper failure was hidden');
        } catch (\RuntimeException $error) {
            $this->assertSame('Private display transform detail', $error->getMessage());
        }
        $this->assertSame(2, $state->refresh()->policy_version);
        $this->assertSame('pending', $state->native_status);
        $this->assertSame($accepted, $state->only(['version', 'digest', 'profile', 'state', 'native_version']));
        FailingProjectionMapper::$fail = false;
        $this->assertSame('applied', $repository->apply($fresh));
        $this->assertSame(4, $state->refresh()->native_version);
    }
}
