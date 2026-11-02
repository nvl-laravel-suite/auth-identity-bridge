<?php

namespace IdentityPlatform\Laravel\Tests\Console;

use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\UserSnapshot;
use IdentityPlatform\Laravel\Sync\UserSnapshotRepository;
use IdentityPlatform\Laravel\Sync\UserSyncRequest;
use IdentityPlatform\Laravel\Sync\UserSyncWorkRepository;
use IdentityPlatform\Laravel\Tests\Sync\ProfileFixture;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

class ReconcileNative extends User
{
    protected $table = 'reconcile_people';

    protected $guarded = [];
}

class ReconcileTraversalTest extends TestCase
{
    public function test_command_traverses_final_provider_page_and_reports_completed_only_after_exhaustion(): void
    {
        $this->configure(['identity.consumers.one.sync.enabled' => true]);
        $lists = 0;
        Http::fake(function ($request) use (&$lists) {
            $subjects = $request->data()['subjects'] ?? null;
            if ($subjects === null) {
                $lists++;
                $subjects = [$lists === 1 ? 'first' : 'last'];
            }

            return Http::response(['contract' => 'platform-consumer-sync.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'profiles' => array_map(fn ($subject) => ['subject' => $subject, 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile()], $subjects), 'nextCursor' => str_ends_with($request->url(), 'profiles.list') && $lists === 1 ? 'next-page' : null]);
        });
        $this->withoutMockingConsoleOutput();
        $exit = Artisan::call('identity:users-reconcile', ['--consumer' => 'one', '--limit' => '100']);
        $result = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);
        $this->assertSame(2, $lists);
        $this->assertSame(0, $exit);
        $this->assertTrue($result['completed']);
        $this->assertSame(2, $result['profiles']);
    }

    public function test_page_budget_never_turns_partial_reconciliation_into_success(): void
    {
        $this->configure(['identity.consumers.one.sync.enabled' => true]);
        Http::fake(['*' => Http::response(['contract' => 'platform-consumer-sync.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'profiles' => [], 'nextCursor' => 'another-page'])]);
        $this->withoutMockingConsoleOutput();
        $exit = Artisan::call('identity:users-reconcile', ['--consumer' => 'one', '--max-pages' => '1']);
        $result = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);
        $this->assertSame(1, $exit);
        $this->assertFalse($result['completed']);
        $this->assertSame('another-page', $result['nextCursor']);
    }

    public function test_repeated_cursor_does_not_loop_unbounded_or_report_success(): void
    {
        $this->configure(['identity.consumers.one.sync.enabled' => true]);
        Http::fake(['*' => Http::response(['contract' => 'platform-consumer-sync.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'profiles' => [], 'nextCursor' => 'same-page'])]);
        $this->withoutMockingConsoleOutput();
        $this->assertSame(1, Artisan::call('identity:users-reconcile', ['--consumer' => 'one']));
        $this->assertStringContainsString('user_sync_cursor_not_advancing', Artisan::output());
        Http::assertSentCount(2);
    }

    public function test_exhausted_pages_with_native_pending_leave_generation_incomplete_and_exit_failure(): void
    {
        Schema::create('reconcile_people', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email');
            $table->timestamps();
        });
        $this->configure(['identity.consumers.one.sync.enabled' => true, 'identity.consumers.one.sync.provision_missing' => true, 'identity.consumers.one.users.model' => ReconcileNative::class, 'identity.consumers.one.users.fields' => ['name' => 'name', 'email' => 'email']]);
        $snapshot = ['subject' => 'person', 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile()];
        $this->graph()->make(UserSnapshotRepository::class)->apply(UserSnapshot::validate($snapshot, 1, $this->graph()->make(IdentityConfig::class)));
        ReconcileNative::firstOrFail()->delete();
        $snapshot['version'] = 2;
        $snapshot['state'] = 'suspended';
        Http::fake(['*' => Http::response(['contract' => 'platform-consumer-sync.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'profiles' => [$snapshot], 'nextCursor' => null])]);
        $this->withoutMockingConsoleOutput();
        $this->assertSame(1, Artisan::call('identity:users-reconcile', ['--consumer' => 'one']));
        $result = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);
        $this->assertFalse($result['completed']);
        $this->assertSame(1, $result['nativePending']);
        $work = UserSyncRequest::where('subject', 'person')->firstOrFail();
        $this->assertLessThan($work->generation, $work->completed_generation);
    }

    public static function bindingGenerationChanges(): array
    {
        return [[false], [true]];
    }

    #[DataProvider('bindingGenerationChanges')]
    public function test_final_page_reports_binding_work_created_or_advanced_during_transport(bool $existing): void
    {
        $this->configure(['identity.consumers.one.sync.enabled' => true]);
        $work = $this->graph()->make(UserSyncWorkRepository::class);
        if ($existing) {
            $work->bindingRequest(true);
        }
        $calls = 0;
        Http::fake(function () use ($work, &$calls) {
            if (++$calls === 1) {
                $work->bindingRequest(true);
            }

            return Http::response(['contract' => 'platform-consumer-sync.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'profiles' => [], 'nextCursor' => null]);
        });
        $this->withoutMockingConsoleOutput();
        $firstExit = Artisan::call('identity:users-reconcile', ['--consumer' => 'one']);
        $first = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);
        $this->assertFalse($first['completed']);
        $this->assertSame(1, $first['pending']);
        $this->assertSame(1, $firstExit);
        $row = $work->bindingRequest();
        $this->assertSame($existing ? 2 : 1, $row->generation);
        $this->assertSame(0, $row->completed_generation);
        $secondExit = Artisan::call('identity:users-reconcile', ['--consumer' => 'one']);
        $second = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);
        $this->assertTrue($second['completed']);
        $this->assertSame(0, $second['pending']);
        $this->assertSame(0, $secondExit);
        $this->assertSame($row->generation, $work->bindingRequest()->completed_generation);
        Http::assertSentCount(2);
    }
}
