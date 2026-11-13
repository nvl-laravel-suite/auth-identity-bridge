<?php

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Delegation\OverlayRepository;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Sync\ImportBinding;
use IdentityPlatform\Laravel\Sync\ImportCheckpointRepository;
use IdentityPlatform\Laravel\Sync\ImportPage;
use IdentityPlatform\Laravel\Sync\ImportRun;
use IdentityPlatform\Laravel\Sync\ImportRunner;
use IdentityPlatform\Laravel\Sync\ProfileSynchronized;
use IdentityPlatform\Laravel\Sync\UserImportEntry;
use IdentityPlatform\Laravel\Sync\UserImportLink;
use IdentityPlatform\Laravel\Sync\UserImportPage;
use IdentityPlatform\Laravel\Sync\UserImportResult;
use IdentityPlatform\Laravel\Sync\UserImportSource;
use IdentityPlatform\Laravel\Sync\UserImportSourceRegistry;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Sync\UserSyncManager;
use IdentityPlatform\Laravel\Sync\UserSyncRequest;
use IdentityPlatform\Laravel\Sync\UserSyncState;
use IdentityPlatform\Laravel\Sync\UserSyncWorkRepository;
use IdentityPlatform\Laravel\Tests\TestCase;
use IdentityPlatform\Laravel\Users\EloquentNativeUserMapper;
use IdentityPlatform\Laravel\Users\ExistingNativeOnlyLifecycle;
use IdentityPlatform\Laravel\Users\IdentityUserResolver;
use IdentityPlatform\Laravel\Users\NativeValueTransform;
use IdentityPlatform\Laravel\Users\RetainedNativeLifecycle;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

class RunnerPerson extends User
{
    protected $guarded = [];
}

class RunnerSource implements UserImportSource
{
    public static array $ids = [];

    public static array $overrides = [];

    public function page(?string $cursor, int $limit): UserImportPage
    {
        $offset = $cursor === null ? 0 : (int) $cursor;
        $slice = array_slice(self::$ids, $offset, $limit);
        $entries = array_map(fn ($id) => new UserImportEntry(['sourceUserId' => 'source-'.$id, 'name' => 'Imported '.$id, 'email' => 'person'.$id.'@example.test', 'emailVerified' => true, 'passwordHash' => '$2y$10$'.str_repeat('a', 53), ...self::$overrides[$id] ?? []], $id), $slice);
        $next = $offset + count($slice);

        return new UserImportPage($entries, $next < count(self::$ids) ? (string) $next : null);
    }
}

class DeletedRunnerPerson extends RunnerPerson
{
    protected $table = 'runner_people';

    use SoftDeletes;
}

class DirectoryMember extends User
{
    protected $table = 'directory_members';

    protected $primaryKey = 'member_key';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = [];
}

class DirectorySource implements UserImportSource
{
    public function page(?string $cursor, int $limit): UserImportPage
    {
        $rows = DirectoryMember::query()->when($cursor !== null, fn ($query) => $query->where('member_key', '>', $cursor))->orderBy('member_key')->limit($limit + 1)->get();
        $batch = $rows->take($limit);

        return new UserImportPage($batch->map(fn ($row) => new UserImportEntry(['sourceUserId' => 'directory-'.$row->member_key, 'name' => $row->display_label, 'email' => $row->contact_address, 'emailVerified' => true], $row->member_key))->all(), $rows->count() > $limit ? $batch->last()->member_key : null);
    }
}

class NullImportName implements NativeValueTransform
{
    public static function validate(array $options): void {}

    public function transform(mixed $value, array $options): mixed
    {
        return null;
    }
}

class FailingImportMapper extends EloquentNativeUserMapper
{
    public static bool $fail = true;

    public function synchronize(Authenticatable $user, IdentityUser $projection): void
    {
        if (self::$fail) {
            throw new \RuntimeException('SECRET-MAPPER');
        }
        parent::synchronize($user, $projection);
    }
}

class FailingFinalCheckpoint extends ImportCheckpointRepository
{
    public static bool $fail = true;

    public function finish(ImportRun $run, ImportPage $page, UserImportResult $result, array $outcomes, array $work): void
    {
        if (self::$fail) {
            self::$fail = false;
            throw new \RuntimeException('SECRET-CHECKPOINT');
        }
        parent::finish($run, $page, $result, $outcomes, $work);
    }
}

class UnavailableCheckpointStore extends ImportCheckpointRepository
{
    public static string $stage = 'accepted';

    public function accepted(ImportRun $run, UserImportResult $result): array
    {
        if (self::$stage === 'accepted') {
            throw new \RuntimeException('SECRET-ACCEPTED-SQL');
        }

        return parent::accepted($run, $result);
    }

    public function finish(ImportRun $run, ImportPage $page, UserImportResult $result, array $outcomes, array $work): void
    {
        throw new \RuntimeException('SECRET-FINAL-SQL');
    }

    public function failed(ImportRun $run, string $code, string $remoteOutcome, int $accepted): void
    {
        throw new \RuntimeException('SECRET-FAILURE-WRITE-SQL');
    }

    public function summary(ImportRun $run): array
    {
        throw new \RuntimeException('SECRET-SUMMARY-SQL');
    }
}

class FailingSummaryCheckpoint extends ImportCheckpointRepository
{
    public function summary(ImportRun $run): array
    {
        throw new \RuntimeException('SECRET-SQL-RESULT');
    }
}

class FailingCheckpoint extends ImportCheckpointRepository
{
    public static bool $fail = true;

    public function accepted(ImportRun $run, UserImportResult $result): array
    {
        if (self::$fail) {
            self::$fail = false;
            throw new \RuntimeException('SECRET-SQL-BODY');
        }

        return parent::accepted($run, $result);
    }
}

class ImportRunnerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('runner_people', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email');
            $table->timestamps();
        });
        $this->configure(['identity.consumers.one.sync.enabled' => true, 'identity.consumers.one.sync.import_enabled' => true, 'identity.consumers.one.users.lifecycle_policy' => ExistingNativeOnlyLifecycle::class, 'identity.consumers.one.users.model' => RunnerPerson::class, 'identity.consumers.one.users.fields' => ['name' => 'name', 'email' => 'email']]);
        RunnerSource::$ids = [];
        RunnerSource::$overrides = [];
        Http::preventStrayRequests();
    }

    private function people(int $count): void
    {
        if ($count <= 0) {
            return;
        }
        $now = now();
        $rows = [];
        for ($i = 1; $i <= $count; $i++) {
            $rows[] = ['name' => 'Local', 'email' => 'local'.$i.'@example.test', 'created_at' => $now, 'updated_at' => $now];
        }
        DB::table('runner_people')->insert($rows);
        RunnerSource::$ids = array_values(array_merge(RunnerSource::$ids, array_slice(RunnerPerson::query()->orderBy('id')->pluck('id')->all(), -$count)));
    }

    private function provider(?\Closure $after = null): void
    {
        Http::fake(function ($request) use ($after) {
            $users = $request->data()['users'];
            $mappings = array_map(fn ($user) => ['sourceUserId' => $user['sourceUserId'], 'subject' => 'id-'.$user['sourceUserId'], 'version' => 1, 'state' => ($user['active'] ?? true) ? 'active' : 'suspended', 'profile' => ProfileFixture::profile(['name' => $user['name'], 'email' => $user['email']])], $users);
            $after?->__invoke();

            return Http::response(['contract' => 'platform-consumer-sync-import.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'mappings' => $mappings]);
        });
    }

    private function runImport(?string $resume = null, bool $dryRun = false, int $maxPages = 1000): array
    {
        return $this->graph()->make(ImportRunner::class)->run('people', new RunnerSource, $resume, $dryRun, 100, $maxPages);
    }

    public function test_101_people_resume_after_page_budget_and_restart_without_duplicate_identities(): void
    {
        $this->people(101);
        $this->provider();
        $first = $this->runImport(maxPages: 1);
        $this->assertFalse($first['completed']);
        $this->assertSame(100, $first['associated']);
        $second = $this->runImport($first['runId']);
        $this->assertTrue($second['completed'], json_encode($second));
        $this->assertSame(101, $second['imported']);
        $this->assertSame(101, $second['associated']);
        $this->assertSame(101, UserImportLink::count());
        $restart = $this->runImport();
        $this->assertTrue($restart['completed']);
        $this->assertSame(101, UserImportLink::count());
        Http::assertSentCount(4);
        $this->assertStringNotContainsString('passwordHash', json_encode(ImportBinding::all()->toArray()));
    }

    public function test_dry_run_performs_no_database_cache_or_transport_writes(): void
    {
        $this->people(101);
        $writes = [];
        DB::listen(function ($query) use (&$writes) {
            if (preg_match('/^(insert|update|delete|create|drop)/i', $query->sql)) {
                $writes[] = $query->sql;
            }
        });
        Cache::shouldReceive('store')->never();
        $result = $this->runImport(dryRun: true);
        $this->assertSame([], $writes);
        $this->assertSame(101, $result['validated']);
        $this->assertSame('unverified', $result['remoteChecks']);
        $this->assertFalse($result['completed']);
        Http::assertNothingSent();
    }

    public function test_provider_commit_then_native_failure_retains_mapping_and_recovers_same_source(): void
    {
        $this->people(1);
        $calls = 0;
        $this->provider(function () use (&$calls): void {
            if (++$calls === 1) {
                RunnerPerson::whereKey(1)->delete();
            }
        });
        $first = $this->runImport();
        $this->assertFalse($first['completed']);
        $this->assertSame(1, $first['imported']);
        $this->assertSame(0, $first['associated']);
        $this->assertSame('id-source-1', ImportBinding::firstOrFail()->subject);
        RunnerPerson::create(['id' => 1, 'name' => 'Recovered', 'email' => 'local@example.test']);
        $this->provider();
        $second = $this->runImport($first['runId']);
        $this->assertTrue($second['completed'], json_encode($second));
        $this->assertSame(1, UserImportLink::count());
        Http::assertSent(fn ($request) => ! isset($request->data()['users'][0]['passwordHash']));
    }

    public function test_changed_native_source_binding_refuses_before_second_transport(): void
    {
        $this->people(2);
        $this->provider();
        $this->runImport();
        RunnerSource::$ids = [2];
        RunnerSource::$overrides[2] = ['sourceUserId' => 'source-1'];
        $result = $this->runImport();
        $this->assertSame('user_import_binding_changed', $result['error']);
        Http::assertSentCount(1);
    }

    public function test_duplicate_source_on_later_page_refuses_and_does_not_claim_completion(): void
    {
        $this->people(101);
        RunnerSource::$overrides[101] = ['sourceUserId' => 'source-1'];
        $this->provider();
        $result = $this->runImport();
        $this->assertSame('user_import_duplicate_source', $result['error']);
        $this->assertFalse($result['completed']);
        Http::assertSentCount(1);
    }

    public function test_credential_dtos_refuse_serialization_and_redact_debugging(): void
    {
        $entry = new UserImportEntry(['sourceUserId' => 'one', 'passwordHash' => 'SECRET-HASH', 'name' => 'SECRET-PROFILE'], 1);
        $page = new UserImportPage([$entry], null);
        foreach ([$entry, $page] as $value) {
            ob_start();
            var_dump($value);
            $debug = ob_get_clean();
            $this->assertStringNotContainsString('SECRET', $debug);
            try {
                serialize($value);
                $this->fail('Credential object serialized');
            } catch (\LogicException) {
                $this->addToAssertionCount(1);
            }
            $this->assertStringNotContainsString('SECRET', json_encode($value));
        }
    }

    public function test_checkpoint_failure_after_remote_commit_preserves_exact_replay_and_known_truth(): void
    {
        $this->people(1);
        $this->provider();
        FailingCheckpoint::$fail = true;
        $this->graph()->bind(ImportCheckpointRepository::class, FailingCheckpoint::class);
        $first = $this->runImport();
        $this->assertSame(1, $first['providerAcceptedInLastAttempt'] ?? 0);
        $this->assertSame(0, $first['imported']);
        $this->assertFalse($first['completed']);
        $this->assertSame(1, ImportBinding::count());
        $this->assertNull(ImportBinding::firstOrFail()->subject);
        $this->assertStringNotContainsString('SECRET', json_encode($first));
        $this->selectConsumer();
        $second = $this->runImport($first['runId']);
        $this->assertTrue($second['completed']);
        $this->assertSame(1, UserImportLink::count());
        Http::assertSentCount(2);
        Http::assertSent(fn ($request) => $request->data()['users'][0]['sourceUserId'] === 'source-1');
    }

    public function test_empty_exhausted_import_cannot_hide_unresolved_known_work(): void
    {
        $work = $this->graph()->make(UserSyncWorkRepository::class);
        $work->request('unresolved');
        $result = $this->runImport();
        $this->assertTrue($result['exhausted']);
        $this->assertFalse($result['completed']);
        $this->assertSame(1, $result['pending']);
        Http::assertNothingSent();
    }

    public function test_missing_native_row_fails_whole_batch_before_transport(): void
    {
        $this->people(2);
        RunnerPerson::whereKey(2)->delete();
        $result = $this->runImport();
        $this->assertSame('user_import_native_missing', $result['error']);
        $this->assertSame(0, ImportBinding::count());
        Http::assertNothingSent();
    }

    public function test_resume_requires_same_source_class_consumer_and_batch_size(): void
    {
        $this->people(1);
        $this->provider();
        $first = $this->runImport();
        foreach ([['another', 100], ['people', 50]] as [$name, $limit]) {
            try {
                $this->graph()->make(ImportRunner::class)->run($name, new RunnerSource, $first['runId'], limit: $limit);
                $this->fail('Foreign run resumed');
            } catch (IdentityException $error) {
                $this->assertSame('user_import_run_invalid', $error->errorCode);
            }
        }
        $this->configure(['identity.consumers.one.browser.client_id' => 'another-client']);
        try {
            $this->runImport($first['runId']);
            $this->fail('Foreign binding resumed');
        } catch (IdentityException $error) {
            $this->assertSame('user_import_run_invalid', $error->errorCode);
        }
        Http::assertSentCount(1);
    }

    public function test_source_exception_text_never_reaches_output_or_checkpoints(): void
    {
        $source = new class implements UserImportSource
        {
            public function page(?string $cursor, int $limit): UserImportPage
            {
                throw new \RuntimeException('SECRET-CREDENTIAL-PROFILE');
            }
        };
        $result = $this->graph()->make(ImportRunner::class)->run('failing', $source);
        $this->assertSame('user_import_unavailable', $result['error']);
        $this->assertStringNotContainsString('SECRET', json_encode($result));
        $this->assertStringNotContainsString('SECRET', json_encode(ImportRun::all()->toArray()));
        Http::assertNothingSent();
    }

    public function test_source_cursor_cycle_and_duplicate_page_are_bounded(): void
    {
        $this->people(1);
        $source = new class implements UserImportSource
        {
            public function page(?string $cursor, int $limit): UserImportPage
            {
                return new UserImportPage([new UserImportEntry(['sourceUserId' => 'source-1', 'name' => 'Person', 'email' => 'person@example.test', 'emailVerified' => true], 1)], $cursor === null ? 'next' : 'next');
            }
        };
        $this->provider();
        $result = $this->graph()->make(ImportRunner::class)->run('cycling', $source);
        $this->assertFalse($result['completed']);
        $this->assertContains($result['error'], ['user_import_duplicate_source', 'user_import_cursor_invalid']);
        Http::assertSentCount(1);
    }

    public function test_second_native_schema_and_registered_adapter_use_public_configuration(): void
    {
        Schema::create('directory_members', function (Blueprint $table): void {
            $table->string('member_key')->primary();
            $table->string('display_label');
            $table->string('contact_address');
            $table->timestamps();
        });
        DirectoryMember::create(['member_key' => '550e8400-e29b-41d4-a716-446655440000', 'display_label' => 'Directory', 'contact_address' => 'directory@example.test']);
        $this->configure(['identity.consumers.one.users.model' => DirectoryMember::class, 'identity.consumers.one.users.fields' => ['name' => 'display_label', 'email' => 'contact_address']]);
        $registry = new UserImportSourceRegistry;
        $registry->register('directory', DirectorySource::class);
        $this->provider();
        $result = $this->graph()->make(ImportRunner::class)->run('directory', $registry->resolve('directory', $this->graph()));
        $this->assertTrue($result['completed'], json_encode($result));
        $this->assertSame(1, UserImportLink::count());
        $this->assertSame('Directory', DirectoryMember::firstOrFail()->display_label);
        try {
            $registry->resolve(DirectorySource::class, $this->graph());
            $this->fail('CLI class selected');
        } catch (IdentityException $error) {
            $this->assertSame('user_import_source_unknown', $error->errorCode);
        }
    }

    public function test_soft_deleted_native_row_is_classified_without_restoration_or_transport(): void
    {
        Schema::table('runner_people', fn (Blueprint $table) => $table->softDeletes());
        $this->people(1);
        DeletedRunnerPerson::firstOrFail()->delete();
        $this->configure(['identity.consumers.one.users.model' => DeletedRunnerPerson::class]);
        $result = $this->runImport();
        $this->assertSame('user_import_native_soft_deleted', $result['error']);
        $this->assertSame(1, DeletedRunnerPerson::onlyTrashed()->count());
        Http::assertNothingSent();
    }

    public function test_registered_transform_and_required_column_fail_before_transport(): void
    {
        $this->people(1);
        $this->configure(['identity.consumers.one.users.fields' => ['name' => ['column' => 'name', 'transform' => NullImportName::class], 'email' => 'email']]);
        $result = $this->runImport();
        $this->assertSame('user_import_native_required', $result['error']);
        $this->assertSame('Local', RunnerPerson::firstOrFail()->name);
        $this->assertSame(0, ImportBinding::count());
        Http::assertNothingSent();
    }

    public function test_native_owner_cannot_be_acquired_with_a_new_source_id(): void
    {
        $this->people(1);
        $this->provider();
        $this->runImport();
        RunnerSource::$overrides[1] = ['sourceUserId' => 'another-source'];
        $result = $this->runImport();
        $this->assertSame('user_import_owner_conflict', $result['error']);
        Http::assertSentCount(1);
    }

    public function test_inactive_acceptance_survives_native_failure_and_retries_without_claiming_convergence(): void
    {
        $this->people(1);
        RunnerSource::$overrides[1] = ['active' => false];
        $this->provider();
        FailingImportMapper::$fail = true;
        $this->configure(['identity.consumers.one.users.mapper' => FailingImportMapper::class]);
        $first = $this->runImport();
        $this->assertSame('suspended', UserSyncState::firstOrFail()->state);
        $this->assertSame(1, $first['nativePending']);
        $this->assertFalse($first['completed']);
        $this->assertSame(0, $first['associated']);
        FailingImportMapper::$fail = false;
        $second = $this->runImport($first['runId']);
        $this->assertTrue($second['completed'], json_encode($second));
        $this->assertSame('suspended', UserSyncState::firstOrFail()->state);
        $this->assertSame(0, $second['nativePending']);
    }

    public function test_delegate_cannot_start_import_or_reconciliation_effects(): void
    {
        $this->people(1);
        $this->graph()->make(OverlayRepository::class)->save('synthetic-session', ['source_sid' => 'sid', 'status' => 'active', 'browser_binding' => 'binding', 'context_version' => 1, 'expires_at' => now()->addMinutes(5)]);
        $request = $this->app['request'];
        $request->setLaravelSession($this->app['session']->driver());
        $request->session()->put('identity.session', 'synthetic-session');
        $this->bindRequest($request);
        Cache::shouldReceive('store')->never();
        foreach ([fn () => $this->runImport(), fn () => $this->graph()->make(UserSyncManager::class)->reconcile()] as $operation) {
            try {
                $operation();
                $this->fail('Delegated operation allowed');
            } catch (IdentityException $error) {
                $this->assertSame('delegation_outbound_forbidden', $error->errorCode);
            }
        }
        $this->assertSame(0, ImportRun::count());
        Http::assertNothingSent();
    }

    public function test_provider_email_collision_is_safe_and_does_not_create_native_associations(): void
    {
        $this->people(1);
        Http::fake(['*' => Http::response(['error' => ['code' => 'consumer_import_email_conflict', 'message' => 'SECRET-UPSTREAM']], 409)]);
        $result = $this->runImport();
        $this->assertSame('consumer_import_email_conflict', $result['error']);
        $this->assertSame(0, $result['imported']);
        $this->assertSame(0, UserImportLink::count());
        $this->assertStringNotContainsString('SECRET', json_encode($result));
        $this->assertSame([['sourceUserId' => 'source-1', 'nativeUserId' => '1']], $result['failedBatch']);
    }

    public static function ambiguousCommitErrors(): array
    {
        return [['consumer_sync_response_too_large', 413], ['consumer_import_snapshot_unavailable', 503], ['SECRET-UPSTREAM-CODE', 409]];
    }

    #[DataProvider('ambiguousCommitErrors')]
    public function test_remote_commit_error_preserves_unknown_and_same_source_recovers(string $code, int $status): void
    {
        $this->people(1);
        $calls = 0;
        $providerIdentities = [];
        Http::fake(function ($request) use (&$calls, &$providerIdentities, $code, $status) {
            $input = $request->data()['users'][0];
            $providerIdentities[$input['sourceUserId']] ??= 'provider-one';
            if (++$calls === 1) {
                return Http::response(['error' => ['code' => $code, 'message' => 'SECRET-RESPONSE']], $status);
            }

            return Http::response(['contract' => 'platform-consumer-sync-import.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'mappings' => [['sourceUserId' => $input['sourceUserId'], 'subject' => $providerIdentities[$input['sourceUserId']], 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile()]]]);
        });
        $first = $this->runImport();
        $this->assertSame('unknown', $first['remoteOutcome']);
        $this->assertSame($code === 'SECRET-UPSTREAM-CODE' ? 'user_import_unavailable' : $code, $first['error']);
        $this->assertSame('unknown', ImportRun::firstOrFail()->remote_status);
        $this->assertSame(1, ImportBinding::count());
        $this->assertSame(0, UserImportLink::count());
        $this->assertStringNotContainsString('SECRET', json_encode($first));
        $second = $this->runImport($first['runId']);
        $this->assertTrue($second['completed'], json_encode($second));
        $this->assertCount(1, $providerIdentities);
        $this->assertSame(1, UserImportLink::count());
    }

    public function test_new_generation_during_native_commit_is_not_completed_by_old_import_attempt(): void
    {
        $this->people(1);
        $this->provider();
        $work = $this->graph()->make(UserSyncWorkRepository::class);
        Event::listen(ProfileSynchronized::class, fn () => $work->request('id-source-1'));
        $result = $this->runImport();
        $this->assertTrue($result['exhausted']);
        $this->assertSame(1, $result['associated']);
        $this->assertSame(1, $result['pending']);
        $this->assertFalse($result['completed']);
        $row = UserSyncRequest::where('subject', 'id-source-1')->firstOrFail();
        $this->assertLessThan($row->generation, $row->completed_generation);
    }

    public function test_known_binding_replay_omits_changed_credential_and_uses_current_provider_profile(): void
    {
        $this->people(1);
        Http::fake(['*' => Http::response(['contract' => 'platform-consumer-sync-import.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'mappings' => [['sourceUserId' => 'source-1', 'subject' => 'provider-current', 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile(['name' => 'Provider current'])]]])]);
        $this->assertTrue($this->runImport()['completed']);
        RunnerSource::$overrides[1] = ['name' => 'Changed source name', 'passwordHash' => '$2y$10$'.str_repeat('b', 53)];
        $this->assertTrue($this->runImport()['completed']);
        $this->assertSame('Provider current', RunnerPerson::firstOrFail()->name);
        $requests = Http::recorded();
        $this->assertArrayNotHasKey('passwordHash', $requests[1][0]->data()['users'][0]);
        $this->assertSame(1, UserImportLink::count());
    }

    public function test_changed_pending_page_order_refuses_before_replaying_transport(): void
    {
        $this->people(2);
        Http::fake(['*' => Http::response(['error' => ['code' => 'consumer_sync_response_too_large']], 413)]);
        $first = $this->runImport();
        RunnerSource::$ids = [2, 1];
        $second = $this->runImport($first['runId']);
        $this->assertSame('user_import_binding_changed', $second['error']);
        $this->assertFalse($second['completed']);
        Http::assertSentCount(1);
    }

    public function test_invalid_batch_size_is_refused_before_source_or_persistence(): void
    {
        foreach ([0, 101] as $limit) {
            try {
                $this->graph()->make(ImportRunner::class)->run('people', new RunnerSource, limit: $limit);
                $this->fail('Invalid batch accepted');
            } catch (IdentityException $error) {
                $this->assertSame('user_import_limit_invalid', $error->errorCode);
            }
        }
        $this->assertSame(0, ImportRun::count());
        Http::assertNothingSent();
    }

    public function test_dry_run_rejects_same_native_owner_on_separate_pages(): void
    {
        $this->people(1);
        $source = new class implements UserImportSource
        {
            public function page(?string $cursor, int $limit): UserImportPage
            {
                return new UserImportPage([new UserImportEntry(['sourceUserId' => $cursor === null ? 'first' : 'second', 'name' => 'Person', 'email' => 'person@example.test', 'emailVerified' => true], 1)], $cursor === null ? 'next' : null);
            }
        };
        try {
            $this->graph()->make(ImportRunner::class)->run('duplicate-native', $source, dryRun: true, limit: 1);
            $this->fail('Duplicate native export accepted');
        } catch (IdentityException $error) {
            $this->assertSame('user_import_owner_conflict', $error->errorCode);
        }
        $this->assertSame(0, ImportRun::count());
        Http::assertNothingSent();
    }

    public function test_late_checkpoint_cannot_regress_a_finished_run_cursor(): void
    {
        $this->people(1);
        $this->provider();
        $result = $this->runImport();
        $finished = ImportRun::findOrFail($result['runId']);
        $late = clone $finished;
        $late->exhausted = false;
        $page = ImportPage::where('run_id', $finished->id)->firstOrFail();
        try {
            $this->graph()->make(ImportCheckpointRepository::class)->advance($late, $page);
            $this->fail('Late checkpoint accepted');
        } catch (IdentityException $error) {
            $this->assertSame('user_import_run_changed', $error->errorCode);
        }
        $this->assertTrue($finished->refresh()->exhausted);
    }

    public function test_checkpoint_read_failure_does_not_expose_driver_details_from_public_runner(): void
    {
        $this->graph()->bind(ImportCheckpointRepository::class, FailingSummaryCheckpoint::class);
        $result = $this->runImport();
        $this->assertSame('user_import_checkpoint_unavailable', $result['error']);
        $this->assertSame(ImportRun::firstOrFail()->id, $result['runId']);
        $this->assertSame('not_attempted', $result['remoteOutcome']);
        $this->assertSame(0, $result['providerAcceptedInLastAttempt']);
        $this->assertFalse($result['completed']);
        $this->assertArrayNotHasKey('associated', $result);
        $this->assertStringNotContainsString('SECRET', json_encode($result));
    }

    public function test_exhausted_import_does_not_hide_pending_binding_reconciliation(): void
    {
        $this->graph()->make(UserSyncWorkRepository::class)->bindingRequest(true);
        $result = $this->runImport();
        $this->assertFalse($result['completed']);
        $this->assertSame(1, $result['pending']);
        Http::assertNothingSent();
    }

    public function test_new_empty_run_does_not_hide_another_unresolved_import_reservation(): void
    {
        $this->people(1);
        Http::fake(['*' => Http::response(['error' => ['code' => 'consumer_import_snapshot_unavailable']], 503)]);
        $this->runImport();
        RunnerSource::$ids = [];
        $result = $this->runImport();
        $this->assertFalse($result['completed']);
        $this->assertSame(1, $result['unresolved']);
    }

    public function test_final_checkpoint_failure_retains_native_commit_truth_and_replays_existing_association(): void
    {
        $this->people(1);
        $this->provider();
        FailingFinalCheckpoint::$fail = true;
        $this->graph()->bind(ImportCheckpointRepository::class, FailingFinalCheckpoint::class);
        $first = $this->runImport();
        $this->assertSame(1, UserImportLink::count());
        $this->assertSame(1, $first['associated']);
        $this->assertFalse($first['completed']);
        $this->assertSame(1, $first['pending']);
        $this->selectConsumer();
        $second = $this->runImport($first['runId']);
        $this->assertTrue($second['completed']);
        $this->assertSame(1, UserImportLink::count());
        $this->assertSame(1, RunnerPerson::count());
    }

    public function test_controlled_import_refuses_automatic_creation_before_even_dry_run(): void
    {
        $this->configure(['identity.consumers.one.users.lifecycle_policy' => RetainedNativeLifecycle::class]);
        foreach ([false, true] as $dryRun) {
            try {
                $this->runImport(dryRun: $dryRun);
                $this->fail('Provisioning remained enabled');
            } catch (IdentityException $error) {
                $this->assertSame('user_import_provisioning_enabled', $error->errorCode);
            }
        }
        $this->assertSame(0, ImportRun::count());
        Http::assertNothingSent();
    }

    public function test_worker_provisioning_flag_also_blocks_controlled_import_with_denial_policy(): void
    {
        $this->configure(['identity.consumers.one.sync.provision_missing' => true]);
        try {
            $this->runImport();
            $this->fail('Worker provisioning remained enabled');
        } catch (IdentityException $error) {
            $this->assertSame('user_import_provisioning_enabled', $error->errorCode);
        }
        $this->assertSame(0, ImportRun::count());
        Http::assertNothingSent();
    }

    public function test_unknown_remote_commit_cannot_jit_create_a_native_row_and_resume_preserves_host_foreign_keys(): void
    {
        $this->people(1);
        Schema::create('runner_records', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('owner_id')->constrained('runner_people');
        });
        DB::table('runner_records')->insert(['owner_id' => 1]);
        $calls = 0;
        Http::fake(function ($request) use (&$calls) {
            if (++$calls === 1) {
                return Http::response(['error' => ['code' => 'consumer_sync_response_too_large']], 413);
            }

            return Http::response(['contract' => 'platform-consumer-sync-import.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'mappings' => [['sourceUserId' => 'source-1', 'subject' => 'provider-committed', 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile()]]]);
        });
        $first = $this->runImport();
        $this->assertSame('unknown', $first['remoteOutcome']);
        $projection = $this->graph()->make(UserSynchronizer::class)->sync(['sub' => 'provider-committed', 'name' => 'Verified', 'email' => 'verified@example.test']);
        $resolver = $this->graph()->make(IdentityUserResolver::class);
        try {
            $resolver->resolve($projection);
            $this->fail('Unassociated JIT identity acquired a native row');
        } catch (IdentityException $error) {
            $this->assertSame('identity_user_provisioning_denied', $error->errorCode);
        }
        $this->assertSame(1, RunnerPerson::count());
        $this->assertSame(0, UserImportLink::count());
        $second = $this->runImport($first['runId']);
        $this->assertTrue($second['completed'], json_encode($second));
        $this->assertSame(1, RunnerPerson::count());
        $this->assertSame(1, $resolver->resolve($projection)->getKey());
        $this->assertSame(1, DB::table('runner_records')->value('owner_id'));
    }

    public static function unavailableCheckpointStages(): array
    {
        return [['accepted'], ['finish']];
    }

    #[DataProvider('unavailableCheckpointStages')]
    public function test_remote_acceptance_survives_checkpoint_and_failure_write_outage(string $stage): void
    {
        $this->people(1);
        $this->provider();
        UnavailableCheckpointStore::$stage = $stage;
        $this->graph()->bind(ImportCheckpointRepository::class, UnavailableCheckpointStore::class);
        try {
            $result = $this->runImport();
        } catch (IdentityException) {
            $this->fail('Known remote acceptance and run reference were discarded');
        }
        $this->assertUnavailableCheckpointResult($result);
        $this->assertSame(1, ImportBinding::count());
        $this->assertSame('source-1', ImportBinding::firstOrFail()->source_user_id);
        $this->assertSame('1', ImportBinding::firstOrFail()->native_user_id);
        $this->assertSame($stage === 'finish' ? 1 : 0, UserImportLink::count());
        $this->selectConsumer();
        $recovered = $this->runImport($result['runId']);
        $this->assertTrue($recovered['completed']);
        $this->assertSame(1, UserImportLink::count());
        $this->assertSame(1, RunnerPerson::count());
        Http::assertSentCount(2);
    }

    public function test_post_commit_summary_outage_preserves_known_remote_acceptance_without_guessing_counts(): void
    {
        $this->people(1);
        $this->provider();
        $this->graph()->bind(ImportCheckpointRepository::class, FailingSummaryCheckpoint::class);
        try {
            $result = $this->runImport();
        } catch (IdentityException) {
            $this->fail('Known committed result and run reference were discarded');
        }
        $this->assertUnavailableCheckpointResult($result);
        $this->assertSame(1, UserImportLink::count());
        $this->assertTrue(ImportRun::firstOrFail()->exhausted);
        $this->selectConsumer();
        $recovered = $this->runImport($result['runId']);
        $this->assertTrue($recovered['completed']);
        $this->assertSame(1, $recovered['associated']);
        Http::assertSentCount(1);
    }

    private function assertUnavailableCheckpointResult(array $result): void
    {
        $this->assertSame(ImportRun::firstOrFail()->id, $result['runId']);
        $this->assertSame('accepted', $result['remoteOutcome']);
        $this->assertSame(1, $result['providerAcceptedInLastAttempt']);
        $this->assertFalse($result['completed']);
        $this->assertSame('user_import_checkpoint_unavailable', $result['error']);
        $this->assertSame('unavailable', $result['checkpointStatus']);
        $this->assertSame([['sourceUserId' => 'source-1', 'nativeUserId' => '1']], $result['failedBatch']);
        foreach (['imported', 'associated', 'applied', 'stale', 'missing', 'pending', 'nativePending', 'unresolved', 'failed', 'exhausted'] as $key) {
            $this->assertArrayNotHasKey($key, $result);
        }
        $this->assertStringNotContainsString('SECRET', json_encode($result));
    }

    public function test_command_prints_safe_known_commit_result_and_resumes_after_store_recovery(): void
    {
        $this->people(1);
        $storeUnavailable = false;
        $calls = 0;
        $this->provider(function () use (&$storeUnavailable, &$calls): void {
            if (++$calls === 1) {
                $storeUnavailable = true;
            }
        });
        DB::listen(function ($query) use (&$storeUnavailable): void {
            if ($storeUnavailable && str_contains($query->sql, 'identity_import_')) {
                throw new \RuntimeException('SECRET-CHECKPOINT-DRIVER');
            }
        });
        $sources = new UserImportSourceRegistry;
        $sources->register('outage', RunnerSource::class);
        $this->app->instance(UserImportSourceRegistry::class, $sources);
        $this->withoutMockingConsoleOutput();
        $exit = Artisan::call('identity:users-import', ['--consumer' => 'one', '--source' => 'outage']);
        $storeUnavailable = false;
        $this->assertSame(1, $exit);
        $result = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);
        $this->assertUnavailableCheckpointResult($result);
        $this->assertSame(0, Artisan::call('identity:users-import', ['--consumer' => 'one', '--source' => 'outage', '--resume' => $result['runId']]));
        $recovered = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);
        $this->assertTrue($recovered['completed']);
        $this->assertSame($result['runId'], $recovered['runId']);
        $this->assertSame(1, UserImportLink::count());
        $this->assertSame(1, RunnerPerson::count());
        Http::assertSentCount(2);
    }
}
