<?php

namespace IdentityPlatform\Laravel\Tests\Sync;

use IdentityPlatform\Laravel\Callbacks\CallbackReceiver;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Sync\ProfileSynchronized;
use IdentityPlatform\Laravel\Sync\RefreshIdentityUser;
use IdentityPlatform\Laravel\Sync\UserSnapshotBatch;
use IdentityPlatform\Laravel\Sync\UserSnapshotRepository;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Sync\UserSyncManager;
use IdentityPlatform\Laravel\Sync\UserSyncRequest;
use IdentityPlatform\Laravel\Sync\UserSyncState;
use IdentityPlatform\Laravel\Sync\UserSyncWorkRepository;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Contracts\Queue\Job;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

class UserSyncWorkTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->configure(['identity.consumers.one.sync.enabled' => true]);
        Queue::fake();
        Http::preventStrayRequests();
    }

    private function response(array $profiles = [], ?string $cursor = null): array
    {
        return ['contract' => 'platform-consumer-sync.v1', 'issuer' => 'https://identity.test/api/auth', 'applicationId' => 'app-1', 'clientId' => 'web-1', 'policyVersion' => 1, 'profiles' => $profiles, 'nextCursor' => $cursor];
    }

    private function entry(string $subject = 'person'): array
    {
        return ['subject' => $subject, 'version' => 1, 'state' => 'active', 'profile' => ProfileFixture::profile(['name' => 'Current', 'email' => 'person@example.test', 'locale' => 'en'])];
    }

    private function event(): array
    {
        $body = json_encode(['schema_version' => 1, 'event_id' => 'event-sync', 'type' => 'profile.invalidated', 'application_id' => 'app-1', 'occurred_at' => gmdate('Y-m-d\TH:i:s\Z'), 'subject' => 'person']);
        $timestamp = (string) time();

        return [$body, ['x-identity-event-id' => 'event-sync', 'x-identity-timestamp' => $timestamp, 'x-identity-signature' => 'v1='.hash_hmac('sha256', 'event-sync.'.$timestamp.'.'.$body, str_repeat('e', 32))]];
    }

    public static function cursorPhases(): array
    {
        return ['known finishes first' => [true, 2, 5], 'listing finishes first' => [false, 2, 5], '203 records known finishes first' => [true, 100, 203], '203 records listing finishes first' => [false, 100, 203]];
    }

    #[DataProvider('cursorPhases')]
    public function test_independent_cursor_phases_converge_without_restarting_an_exhausted_scan(bool $knownAhead, int $limit, int $count): void
    {
        $work = app(UserSyncWorkRepository::class);
        $subjects = array_map(fn ($index) => sprintf('person-%03d', $index), range(1, $count));
        $knownCursor = $knownAhead ? $subjects[$limit - 1] : null;
        $listCursor = $knownAhead ? null : 'page-'.$limit;
        foreach ($subjects as $subject) {
            $work->complete($work->register($subject));
        }
        $work->binding()->update(['policy_version' => 1, 'cycle_policy_version' => 1, 'cycle_generation' => 1, 'known_cursor' => $knownCursor, 'list_cursor' => $listCursor]);
        $work->bindingRequest(true);
        Http::fake(function ($request) use ($subjects) {
            if (str_ends_with($request->url(), 'profiles.read')) {
                return Http::response($this->response(array_map(fn ($subject) => $this->entry($subject), $request['subjects'])));
            }
            $offset = (int) str_replace('page-', '', $request['cursor'] ?? '0');
            $page = array_slice($subjects, $offset, $request['limit']);
            $next = $offset + count($page);

            return Http::response($this->response(array_map(fn ($subject) => $this->entry($subject), $page), $next < count($subjects) ? 'page-'.$next : null));
        });

        for ($page = 0; $page < 3; $page++) {
            $result = app(UserSyncManager::class)->reconcile($limit);
            $this->assertLessThanOrEqual($limit, $result['known']);
            $this->assertLessThanOrEqual($limit, $result['profiles']);
            if ($page < 2) {
                $this->assertFalse($result['completed']);
            }
        }
        $this->assertSame(0, $work->pendingCount());
        $this->assertTrue($result['completed']);
        $this->assertSame(0, $result['pending']);
        $this->assertSame($count, UserSyncRequest::where('kind', 'subject')->count());
        $this->assertSame($work->bindingRequest()->generation, $work->bindingRequest()->completed_generation);
    }

    public function test_omitted_previously_completed_subject_stays_pending_after_known_scan_finishes(): void
    {
        $work = app(UserSyncWorkRepository::class);
        $work->complete($work->register('person-01'));
        $work->complete($work->register('person-02'));
        $omit = true;
        Http::fake(function ($request) use (&$omit) {
            if (str_ends_with($request->url(), 'profiles.read')) {
                $subjects = array_filter($request['subjects'], fn ($subject) => ! $omit || $subject !== 'person-01');

                return Http::response($this->response(array_values(array_map(fn ($subject) => $this->entry($subject), $subjects))));
            }
            $offset = match ($request['cursor'] ?? null) {
                'page-1' => 1, 'page-2' => 2, default => 0
            };

            return Http::response($this->response([], $offset < 2 ? 'page-'.($offset + 1) : null));
        });
        $first = app(UserSyncManager::class)->reconcile(1);
        $this->assertSame(1, $first['missing']);
        $this->assertFalse($first['completed']);
        app(UserSyncManager::class)->reconcile(1);
        $last = app(UserSyncManager::class)->reconcile(1);
        $this->assertFalse($last['completed']);
        $this->assertSame(1, $last['pending']);
        $row = UserSyncRequest::where('subject', 'person-01')->firstOrFail();
        $this->assertLessThan($row->generation, $row->completed_generation);
        $this->assertSame('user_sync_subject_missing', $row->last_error);

        $omit = false;
        for ($page = 0; $page < 3; $page++) {
            $last = app(UserSyncManager::class)->reconcile(1);
        }
        $this->assertTrue($last['completed']);
        $this->assertSame(0, $last['pending']);
    }

    public static function emptyScanSides(): array
    {
        return ['initial known set empty' => [false], 'directory empty' => [true]];
    }

    #[DataProvider('emptyScanSides')]
    public function test_empty_side_waits_for_other_scan_and_next_cycle_discovers_current_data(bool $emptyDirectory): void
    {
        $subjects = ['person-01', 'person-02', 'person-03'];
        $work = app(UserSyncWorkRepository::class);
        if ($emptyDirectory) {
            foreach ($subjects as $subject) {
                $work->complete($work->register($subject));
            }
        }
        $version = 1;
        Http::fake(function ($request) use (&$subjects, &$version, $emptyDirectory) {
            $reading = str_ends_with($request->url(), 'profiles.read');
            $offset = (int) str_replace('page-', '', $request['cursor'] ?? '0');
            $page = $reading ? $request['subjects'] : ($emptyDirectory ? [] : array_slice($subjects, $offset, $request['limit']));
            $profiles = array_map(function ($subject) use ($version) {
                $entry = $this->entry($subject);
                $entry['version'] = $version;
                if ($version > 1 && $subject === 'person-01') {
                    $entry['state'] = 'revoked';
                    $entry['profile'] = null;
                }

                return $entry;
            }, $page);
            $next = ! $reading && ! $emptyDirectory && $offset + count($page) < count($subjects) ? 'page-'.($offset + count($page)) : null;
            $response = $this->response($profiles, $next);
            $response['policyVersion'] = $version;

            return Http::response($response);
        });
        for ($page = 0; $page < 3; $page++) {
            $result = app(UserSyncManager::class)->reconcile(1);
            $this->assertSame($page === 2, $result['completed']);
        }
        $this->assertSame(3, UserSyncRequest::where('kind', 'subject')->count());
        $version = 2;
        $subjects[] = 'person-04';
        if ($emptyDirectory) {
            $work->request('person-04');
        }
        // A changed policy restarts the whole traversal after accepting current facts.
        $changed = app(UserSyncManager::class)->reconcile(1);
        $this->assertFalse($changed['completed']);
        $this->assertSame($emptyDirectory ? 2 : 1, $changed['pending']);
        for ($page = 0; $page < 4; $page++) {
            $result = app(UserSyncManager::class)->reconcile(1);
            $this->assertSame($page === 3, $result['completed']);
        }
        $this->assertSame(4, UserSyncRequest::where('kind', 'subject')->count());
        $state = UserSyncState::where('subject', 'person-01')->firstOrFail();
        $this->assertSame('revoked', $state->state);
        $this->assertSame(2, $state->version);
        $this->assertSame(2, $state->policy_version);
        $this->assertSame(0, $result['pending']);
    }

    public function test_new_subject_and_binding_generations_during_last_page_remain_pending_until_next_cycle(): void
    {
        $work = app(UserSyncWorkRepository::class);
        $work->complete($work->register('person'));
        $work->bindingRequest(true);
        $invalidate = true;
        Http::fake(function ($request) use ($work, &$invalidate) {
            if (str_ends_with($request->url(), 'profiles.read')) {
                return Http::response($this->response([$this->entry()]));
            }
            if ($invalidate) {
                $invalidate = false;
                $work->request('person');
                $work->bindingRequest(true);
            }

            return Http::response($this->response());
        });
        $first = app(UserSyncManager::class)->reconcile(1);
        $this->assertFalse($first['completed']);
        $this->assertSame(2, $first['pending']);
        $this->assertLessThan($work->bindingRequest()->generation, $work->bindingRequest()->completed_generation);
        $second = app(UserSyncManager::class)->reconcile(1);
        $this->assertTrue($second['completed']);
        $this->assertSame(0, $second['pending']);
    }

    public function test_failure_after_known_exhaustion_keeps_progress_and_retry_finishes_without_restarting_known(): void
    {
        $work = app(UserSyncWorkRepository::class);
        $work->complete($work->register('person'));
        $listCalls = 0;
        Http::fake(function ($request) use (&$listCalls) {
            if (str_ends_with($request->url(), 'profiles.read')) {
                return Http::response($this->response([$this->entry()]));
            }
            $listCalls++;

            return $listCalls === 2 ? Http::response([], 503) : Http::response($this->response([], $listCalls === 1 ? 'page-1' : null));
        });
        $this->assertFalse(app(UserSyncManager::class)->reconcile(1)['completed']);
        $this->assertTrue($work->binding()->known_exhausted);
        try {
            app(UserSyncManager::class)->reconcile(1);
            $this->fail('Failed page accepted');
        } catch (IdentityException $error) {
            $this->assertSame(503, $error->status);
        }
        $this->assertTrue($work->binding()->known_exhausted);
        $this->assertSame('page-1', $work->binding()->list_cursor);
        $this->assertTrue(app(UserSyncManager::class)->reconcile(1)['completed']);
        $this->assertFalse($work->binding()->known_exhausted);
        $this->assertFalse($work->binding()->list_exhausted);
        $this->assertCount(1, Http::recorded(fn ($request) => str_ends_with($request->url(), 'profiles.read')));
    }

    public function test_additive_exhaustion_migration_preserves_existing_binding_and_subject_work(): void
    {
        $work = app(UserSyncWorkRepository::class);
        $row = $work->request('person');
        $binding = $work->binding();
        $binding->update(['policy_version' => 7, 'known_cursor' => 'person', 'list_cursor' => 'page-1']);
        $before = $binding->refresh()->getAttributes();
        unset($before['list_exhausted'], $before['known_exhausted'], $before['cycle_generation'], $before['cycle_policy_version'], $before['progress_version']);
        $request = $row->getAttributes();
        $migration = require __DIR__.'/../../database/migrations/2026_11_02_000000_add_identity_user_sync_exhaustion.php';
        $migration->down();
        $migration->up();
        $after = $binding->refresh()->getAttributes();
        unset($after['list_exhausted'], $after['known_exhausted'], $after['cycle_generation'], $after['cycle_policy_version'], $after['progress_version']);
        $this->assertSame($before, $after);
        $this->assertSame($request, $row->refresh()->getAttributes());
        $this->assertFalse($binding->list_exhausted);
        $this->assertFalse($binding->known_exhausted);
    }

    public static function cycleInvalidations(): array
    {
        return ['new binding generation' => [false], 'new accepted policy' => [true]];
    }

    #[DataProvider('cycleInvalidations')]
    public function test_new_cycle_invalidation_rescans_prefix_before_retained_directory_cursor(bool $policyChange): void
    {
        $work = app(UserSyncWorkRepository::class);
        $work->complete($work->register('person-02'));
        $work->bindingRequest(true);
        $subjects = ['person-02', 'person-03', 'person-04'];
        $policy = 1;
        Http::fake(function ($request) use (&$subjects, &$policy) {
            $reading = str_ends_with($request->url(), 'profiles.read');
            $remaining = array_values(array_filter($subjects, fn ($subject) => ! isset($request['cursor']) || $subject > $request['cursor']));
            $page = $reading ? $request['subjects'] : array_slice($remaining, 0, $request['limit']);
            $response = $this->response(array_map(fn ($subject) => $this->entry($subject), $page), ! $reading && count($remaining) > count($page) ? end($page) : null);
            $response['policyVersion'] = $policy;

            return Http::response($response);
        });
        $this->assertFalse(app(UserSyncManager::class)->reconcile(1)['completed']);
        $this->assertTrue($work->binding()->known_exhausted);
        $this->assertSame('person-02', $work->binding()->list_cursor);
        array_unshift($subjects, 'person-01');
        if ($policyChange) {
            $policy = 2;
            $response = $this->response();
            $response['policyVersion'] = 2;
            app(UserSnapshotRepository::class)->applyBatch(UserSnapshotBatch::validate($response, app(IdentityConfig::class)));
        } else {
            $work->bindingRequest(true);
        }
        for ($page = 0; $page < 4; $page++) {
            $result = app(UserSyncManager::class)->reconcile(1);
            $this->assertSame($page === 3, $result['completed']);
        }
        $this->assertDatabaseHas('identity_user_sync_states', ['subject' => 'person-01', 'policy_version' => $policy]);
        $this->assertSame(0, $result['pending']);
        $this->assertSame($work->bindingRequest()->generation, $work->bindingRequest()->completed_generation);
    }

    public function test_policy_change_between_known_and_directory_pages_requires_a_fresh_cycle(): void
    {
        $work = app(UserSyncWorkRepository::class);
        $work->complete($work->register('person'));
        $policy = 1;
        Http::fake(function ($request) use (&$policy) {
            if (str_ends_with($request->url(), 'profiles.list')) {
                $policy = 2;
            }
            $response = $this->response([$this->entry()]);
            $response['policyVersion'] = $policy;

            return Http::response($response);
        });
        $first = app(UserSyncManager::class)->reconcile(1);
        $this->assertFalse($first['completed']);
        $this->assertNull($work->binding()->list_cursor);
        $this->assertNull($work->binding()->known_cursor);
        $this->assertTrue(app(UserSyncManager::class)->reconcile(1)['completed']);
        $this->assertSame(2, $work->binding()->policy_version);
    }

    public function test_stale_progress_snapshot_cannot_publish_after_an_identical_cursor_cycle(): void
    {
        $work = app(UserSyncWorkRepository::class);
        $old = $work->binding();
        $work->publishProgress($old, null, null, null, 1, false, static function (): void {});
        try {
            $work->publishProgress($old, null, null, null, 1, true, static function (): void {});
            $this->fail('Old progress published after cursor ABA');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_cursor_changed', $error->errorCode);
        }
    }

    public function test_unknown_inherited_cycle_restarts_bounded_scans_without_replacing_existing_work_or_projection(): void
    {
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'person-01', 'name' => 'Before']);
        $work = app(UserSyncWorkRepository::class);
        $row = UserSyncRequest::where('subject', 'person-01')->firstOrFail();
        $work->binding()->update(['known_cursor' => 'person-99', 'list_cursor' => 'page-old']);
        Http::fake(function ($request) {
            if (str_ends_with($request->url(), 'profiles.read')) {
                $this->assertSame(['person-01'], $request['subjects']);
            } else {
                $this->assertArrayNotHasKey('cursor', $request->data());
            }

            return Http::response($this->response([$this->entry('person-01')]));
        });
        $this->assertTrue(app(UserSyncManager::class)->reconcile(1)['completed']);
        $this->assertSame($row->id, UserSyncRequest::where('subject', 'person-01')->firstOrFail()->id);
        $this->assertSame($row->generation, $row->refresh()->generation);
        $this->assertSame($projection->id, IdentityUser::where('subject', 'person-01')->firstOrFail()->id);
        $this->assertSame('Current', $projection->refresh()->name);
        $this->assertSame(0, $work->pendingCount());
    }

    public function test_independent_binding_cycles_cannot_reset_or_complete_each_other(): void
    {
        $second = config('identity.consumers.one');
        $second['app_origin'] = 'https://second.test';
        $second['application_id'] = 'app-2';
        $second['browser']['client_id'] = 'web-2';
        $second['browser']['redirect_uri'] = 'https://second.test/auth/callback';
        $second['browser']['post_logout_redirect_uri'] = 'https://second.test/signed-out';
        $second['routes']['event_uri'] = 'https://second.test/identity/events';
        $second['routes']['backchannel_logout_uri'] = 'https://second.test/auth/backchannel-logout';
        $second['routes']['guard'] = 'identity_two';
        $second['session']['cookie'] = '__Host-two';
        $this->configure(['identity.consumers.two' => $second]);
        $firstWork = app(UserSyncWorkRepository::class);
        $firstWork->request('person');
        $firstWork->bindingRequest(true);
        $selected = 1;
        Http::fake(function ($request) use (&$selected) {
            $response = $this->response($selected === 1 ? [$this->entry()] : []);
            $response['applicationId'] = 'app-'.$selected;
            $response['clientId'] = 'web-'.$selected;
            if ($selected === 1 && str_ends_with($request->url(), 'profiles.list') && ! isset($request['cursor'])) {
                $response['nextCursor'] = 'page-1';
            }

            return Http::response($response);
        });
        $this->assertFalse(app(UserSyncManager::class)->reconcile(1)['completed']);
        $firstProgress = $firstWork->binding()->getAttributes();
        $this->selectConsumer('two');
        $selected = 2;
        $secondWork = app(UserSyncWorkRepository::class);
        $secondWork->bindingRequest(true);
        $this->assertTrue(app(UserSyncManager::class)->reconcile(1)['completed']);
        $this->assertSame($firstProgress, $firstWork->binding()->getAttributes());
        $this->assertLessThan($firstWork->bindingRequest()->generation, $firstWork->bindingRequest()->completed_generation);
        $secondProgress = $secondWork->binding()->getAttributes();
        $this->selectConsumer('one');
        $selected = 1;
        $this->assertTrue(app(UserSyncManager::class)->reconcile(1)['completed']);
        $this->assertSame($secondProgress, $secondWork->binding()->getAttributes());
        $this->assertSame(0, $firstWork->pendingCount());
        $this->assertSame(0, $secondWork->pendingCount());
    }

    public function test_webhook_work_and_job_publish_only_after_commit_and_duplicate_does_not_requeue(): void
    {
        app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'Before']);
        $connection = (new UserSyncRequest)->getConnection();
        [$body,$headers] = $this->event();
        $connection->beginTransaction();
        app(CallbackReceiver::class)->event($body, $headers);
        Queue::assertNothingPushed();
        $connection->rollBack();
        $this->assertDatabaseCount('identity_inbox', 0);
        $this->assertSame(1, UserSyncRequest::firstOrFail()->generation);
        Queue::assertNothingPushed();
        $connection->beginTransaction();
        app(CallbackReceiver::class)->event($body, $headers);
        Queue::assertNothingPushed();
        $connection->commit();
        Queue::assertPushed(RefreshIdentityUser::class, 1);
        $row = UserSyncRequest::firstOrFail();
        Queue::assertPushed(RefreshIdentityUser::class, fn ($job) => $job->requestId === $row->id && ! str_contains(serialize($job), 'Before'));
        app(CallbackReceiver::class)->event($body, $headers);
        Queue::assertPushed(RefreshIdentityUser::class, 1);
    }

    public function test_missing_snapshot_and_rate_limit_retain_pending_work_and_profile(): void
    {
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'Before']);
        $id = app(UserSyncManager::class)->request('person');
        Http::fakeSequence()->push($this->response())->push([], 429, ['Retry-After' => '60']);
        try {
            app(UserSyncManager::class)->process($id);
            $this->fail('Missing subject accepted');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_subject_missing', $error->errorCode);
        }
        $this->assertSame('Before', $projection->refresh()->name);
        $this->assertSame(0, UserSyncRequest::find($id)->completed_generation);
        try {
            app(UserSyncManager::class)->process($id);
            $this->fail('Rate limit accepted');
        } catch (IdentityException $error) {
            $this->assertSame(60, $error->retryAfter);
        }
        $this->assertSame('Before', $projection->refresh()->name);
        $this->assertSame('rate_limited', UserSyncRequest::find($id)->last_error);
    }

    public function test_application_event_records_one_bounded_reconciliation_job_without_fanout(): void
    {
        foreach (['first', 'second', 'third'] as $subject) {
            app(UserSynchronizer::class)->sync(['sub' => $subject]);
        }
        $body = json_encode(['schema_version' => 1, 'event_id' => 'event-app', 'type' => 'application.configured', 'application_id' => 'app-1', 'occurred_at' => gmdate('Y-m-d\TH:i:s\Z'), 'subject' => null]);
        $timestamp = (string) time();
        app(CallbackReceiver::class)->event($body, ['x-identity-event-id' => 'event-app', 'x-identity-timestamp' => $timestamp, 'x-identity-signature' => 'v1='.hash_hmac('sha256', 'event-app.'.$timestamp.'.'.$body, str_repeat('e', 32))]);
        Queue::assertPushed(RefreshIdentityUser::class, 1);
        $this->assertSame(1, UserSyncRequest::where('kind', 'binding')->count());
    }

    public function test_reconciliation_persists_cursor_and_does_not_advance_on_failed_page_then_recovers(): void
    {
        $pages = 0;
        $cursor = 'v1.'.str_repeat('A', 350).'.'.str_repeat('B', 24);
        Http::fake(function ($request) use (&$pages, $cursor) {
            if (str_ends_with($request->url(), 'profiles.read')) {
                return Http::response($this->response(array_map(fn ($subject) => $this->entry($subject), $request['subjects'])));
            }
            $pages++;

            return $pages === 2 ? Http::response([], 503) : Http::response($this->response([$this->entry($pages === 1 ? 'person' : 'second')], $pages === 1 ? $cursor : null));
        });
        $manager = app(UserSyncManager::class);
        $first = $manager->reconcile(1);
        $this->assertSame($cursor, $first['nextCursor']);
        $this->assertSame('text', Schema::getColumnType('identity_user_sync_bindings', 'list_cursor'));
        $this->assertFalse($first['completed']);
        try {
            $manager->reconcile(1);
            $this->fail('Failed page accepted');
        } catch (IdentityException $error) {
            $this->assertSame(503, $error->status);
        }
        $last = $manager->reconcile(1);
        $this->assertTrue($last['completed']);
        $requests = Http::recorded(fn ($request) => str_ends_with($request->url(), 'profiles.list'))->values();
        $this->assertSame($cursor, $requests[1][0]['cursor']);
        $this->assertSame($cursor, $requests[2][0]['cursor']);
    }

    public function test_reconciliation_lost_lease_cannot_publish_cursor_progress(): void
    {
        $key = 'identity-user-sync:'.app(IdentityConfig::class)->bindingHash();
        Http::fake(function () use ($key) {
            Cache::store('identity_tests')->lock($key, 60)->forceRelease();

            return Http::response($this->response([$this->entry()], 'person'));
        });
        try {
            app(UserSyncManager::class)->reconcile(1);
            $this->fail('Lost lease published progress');
        } catch (IdentityException $error) {
            $this->assertSame('user_sync_busy', $error->errorCode);
        }
        $this->assertNull(app(UserSyncWorkRepository::class)->binding()->list_cursor);
    }

    public function test_lost_job_dispatch_is_repaired_by_bounded_reconciliation(): void
    {
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'Before']);
        Queue::shouldReceive('connection')->andThrow(new \RuntimeException('synthetic queue unavailable'));
        Queue::shouldReceive('releaseUniqueJobLocks')->andReturnNull();
        $id = app(UserSyncManager::class)->request('person');
        $this->assertSame(0, UserSyncRequest::find($id)->completed_generation);
        Queue::fake();
        Http::fake(['*' => Http::response($this->response([$this->entry()]))]);
        $result = app(UserSyncManager::class)->reconcile(1);
        $this->assertTrue($result['completed']);
        $this->assertSame('Current', $projection->refresh()->name);
        $row = UserSyncRequest::find($id);
        $this->assertSame($row->generation, $row->completed_generation);
    }

    public function test_jit_registration_failure_rolls_back_projection_and_profile_hook(): void
    {
        $events = [];
        Event::listen(ProfileSynchronized::class, function ($event) use (&$events) {
            $events[] = $event;
        });
        DB::listen(function ($query) {
            if (str_starts_with($query->sql, 'insert into "identity_user_sync_requests"')) {
                throw new \RuntimeException('synthetic registration failure');
            }
        });
        try {
            app(UserSynchronizer::class)->sync(['sub' => 'atomic-person']);
            $this->fail('Registration failure accepted');
        } catch (\RuntimeException) {
        }
        $this->assertSame(0, IdentityUser::where('subject', 'atomic-person')->count());
        $this->assertSame([], $events);
    }

    public function test_job_releases_with_bounded_retry_after_and_keeps_durable_work(): void
    {
        app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'Before']);
        $id = app(UserSyncManager::class)->request('person');
        Http::fake(['*' => Http::response([], 429, ['Retry-After' => '60'])]);
        $queued = \Mockery::mock(Job::class);
        $queued->shouldReceive('release')->once()->with(60);
        $job = new RefreshIdentityUser($id);
        $job->setJob($queued);
        $this->app->call([$job, 'handle']);
        $row = UserSyncRequest::find($id);
        $this->assertSame('rate_limited', $row->last_error);
        $this->assertSame(0, $row->completed_generation);
    }

    public function test_late_failed_job_cannot_overwrite_newer_successful_work_receipt(): void
    {
        $projection = app(UserSynchronizer::class)->sync(['sub' => 'person', 'name' => 'Before']);
        $manager = app(UserSyncManager::class);
        $id = $manager->request('person');
        Http::fake(function () {
            $work = app(UserSyncWorkRepository::class);
            $newer = $work->request('person');
            $entry = $this->entry();
            $entry['version'] = 2;
            app(UserSnapshotRepository::class)->applyBatch(UserSnapshotBatch::validate($this->response([$entry]), app(IdentityConfig::class)));
            $work->complete($newer);

            return Http::response([], 503);
        });
        try {
            $manager->process($id);
            $this->fail('Old failed transport accepted');
        } catch (IdentityException $error) {
            $this->assertSame(503, $error->status);
        }
        $row = UserSyncRequest::find($id);
        $this->assertSame($row->generation, $row->completed_generation);
        $this->assertNull($row->last_error);
        $this->assertSame(0, $row->attempts);
        $this->assertSame('Current', $projection->refresh()->name);
    }

    public function test_reconciliation_command_reports_partial_json_and_failure_exit_for_missing_subject(): void
    {
        app(UserSyncManager::class)->request('omitted-contact');
        Http::fake(['*' => Http::response($this->response())]);

        $this->withoutMockingConsoleOutput();
        $exit = Artisan::call('identity:users-reconcile', ['--limit' => 1, '--consumer' => 'one']);
        $result = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);
        $this->assertSame(1, $exit);
        $this->assertSame(1, $result['missing']);
        $this->assertFalse($result['completed']);
        Http::assertSent(fn ($request) => str_ends_with($request->url(), 'profiles.list'));
    }
}
