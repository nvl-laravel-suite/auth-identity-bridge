<?php

namespace IdentityPlatform\Laravel\Tests\Console;

use IdentityPlatform\Laravel\Sync\ImportRun;
use IdentityPlatform\Laravel\Sync\UserImportPage;
use IdentityPlatform\Laravel\Sync\UserImportSource;
use IdentityPlatform\Laravel\Sync\UserImportSourceRegistry;
use IdentityPlatform\Laravel\Tests\TestCase;
use IdentityPlatform\Laravel\Users\ExistingNativeOnlyLifecycle;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;

class EmptyImportSource implements UserImportSource
{
    public function page(?string $cursor, int $limit): UserImportPage
    {
        return new UserImportPage([], null);
    }
}

class ImportCommandTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->configure(['identity.consumers.one.sync.enabled' => true, 'identity.consumers.one.sync.import_enabled' => true, 'identity.consumers.one.users.lifecycle_policy' => ExistingNativeOnlyLifecycle::class]);
        $registry = new UserImportSourceRegistry;
        $registry->register('empty', EmptyImportSource::class);
        $this->app->instance(UserImportSourceRegistry::class, $registry);
        $this->withoutMockingConsoleOutput();
        Http::preventStrayRequests();
    }

    public function test_registered_source_dry_run_reports_unverified_remote_checks_without_run(): void
    {
        $this->assertSame(0, Artisan::call('identity:users-import', ['--consumer' => 'one', '--source' => 'empty', '--dry-run' => true]));
        $result = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);
        $this->assertSame('unverified', $result['remoteChecks']);
        $this->assertFalse($result['completed']);
        $this->assertSame(0, ImportRun::count());
        Http::assertNothingSent();
    }

    public function test_command_needs_explicit_consumer_and_refuses_arbitrary_class_name(): void
    {
        $this->assertSame(1, Artisan::call('identity:users-import', ['--source' => 'empty']));
        $this->assertStringContainsString('consumer_selection_required', Artisan::output());
        $this->assertSame(1, Artisan::call('identity:users-import', ['--consumer' => 'one', '--source' => EmptyImportSource::class]));
        $this->assertStringContainsString('user_import_source_unknown', Artisan::output());
        $this->assertSame(1, Artisan::call('identity:users-import', ['--consumer' => 'unregistered', '--source' => 'empty']));
        $this->assertStringContainsString('unknown_consumer', Artisan::output());
        $this->assertSame(0, ImportRun::count());
        Http::assertNothingSent();
    }

    public function test_cli_run_reference_requires_exact_registered_source(): void
    {
        $this->assertSame(0, Artisan::call('identity:users-import', ['--consumer' => 'one', '--source' => 'empty']));
        $result = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);
        $this->assertTrue($result['completed']);
        $this->assertSame(0, Artisan::call('identity:users-import', ['--consumer' => 'one', '--source' => 'empty', '--resume' => $result['runId']]));
        $this->assertSame(1, ImportRun::count());
        Http::assertNothingSent();
    }
}
