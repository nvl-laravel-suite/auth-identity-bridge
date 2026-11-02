<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Postgres;

use Carbon\CarbonImmutable;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextManager;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextProvider;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextRegistry;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextResource;
use IdentityPlatform\Laravel\ApplicationContext\ApplicationContextScope;
use IdentityPlatform\Laravel\Authorization\OrdinaryActionRunner;
use IdentityPlatform\Laravel\Authorization\Principal;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Process\Process;

/** Synthetic upstream authority; real local PostgreSQL locks and package write fences. */
class ApplicationContextPostgresTest extends TestCase
{
    use UsesIsolatedPostgres {
        defineEnvironment as private definePostgresEnvironment;
        tearDownInteractsWithMigrations as private tearDownPostgresMigrations;
    }

    private ?array $contenderInput = null;

    private array $workers = [];

    private array $fixtureDirectories = [];

    protected function defineEnvironment($app): void
    {
        $this->definePostgresEnvironment($app);
        $this->fixtureDirectories = [$app['config']->get('identity.consumers.one.session.files'), $app['config']->get('cache.stores.identity_tests.path')];
        if ($this->contenderInput !== null) {
            // Only the parent owns schema creation and teardown. The child uses that exact prefix.
            $app['config']->set('database.connections.qualification', $this->contenderInput['connection']);
        }
        $two = $app['config']->get('identity.consumers.one');
        $two['app_origin'] = 'https://second.test';
        $two['browser']['client_id'] = 'web-2';
        $two['browser']['redirect_uri'] = 'https://second.test/auth/callback';
        $two['browser']['post_logout_redirect_uri'] = 'https://second.test/signed-out';
        $two['routes']['guard'] = 'identity_two';
        $two['routes']['event_uri'] = 'https://second.test/identity/events';
        $two['routes']['backchannel_logout_uri'] = 'https://second.test/auth/backchannel-logout';
        $two['session']['cookie'] = '__Host-two';
        $app['config']->set('identity.consumers.two', $two);
        $app['config']->set('database.connections.qualification_blocker', $app['config']->get('database.connections.qualification'));
    }

    protected function defineDatabaseMigrations(): void
    {
        if ($this->contenderInput === null) {
            parent::defineDatabaseMigrations();
        }
    }

    protected function setUp(): void
    {
        parent::setUp();
        foreach (['one', 'two'] as $name) {
            app(ApplicationContextRegistry::class)->register($name, 'workspace', PostgresWorkspaceFixture::class);
        }
        Http::preventStrayRequests();
        // Each graph receives a finite, exactly bound ordinary decision, never live upstream authority.
        Http::fake(['https://identity.test/api/authorization/snapshot' => function () {
            $config = app(IdentityConfig::class);
            $name = $config->context()->name();

            return Http::response(['contract' => 'platform-authorization-snapshot.v1', 'issuer' => $config->issuer(), 'subject' => 'actor',
                'central_session_id' => 'central-'.$name, 'application_id' => $config->applicationId(), 'client_id' => $config->clientId(),
                'principal_kind' => 'user', 'session_status' => 'active', 'security_version' => 1, 'identity_status' => 'active',
                'application_status' => 'active', 'grant_status' => 'active', 'organization_id' => null, 'selected_role_id' => null,
                'client_policy_version' => 1, 'role_ids' => [], 'roles' => [], 'permissions' => ['documents.update'],
                'authz_version' => 1, 'application_policy_version' => 1, 'issued_at' => gmdate('Y-m-d\TH:i:s\Z'),
                'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 59), 'assurance' => null, 'delegation' => null]);
        }]);
        if ($this->contenderInput !== null) {
            return;
        }
        foreach (['p12_resources', 'p12_memberships', 'p12_documents', 'p12_attempts', 'p12_audit', 'p12_outbox'] as $table) {
            Schema::create($table, function (Blueprint $blueprint) use ($table): void {
                $blueprint->string('binding_hash');
                $blueprint->string('resource_id');
                $blueprint->primary(['binding_hash', 'resource_id']);
                if ($table === 'p12_resources') {
                    $blueprint->string('label');
                    $blueprint->string('version');
                } elseif ($table === 'p12_memberships') {
                    $blueprint->string('actor');
                    $blueprint->string('organization_id')->nullable();
                    $blueprint->string('role_id')->nullable();
                    $blueprint->string('version');
                } elseif ($table === 'p12_documents') {
                    $blueprint->string('owner');
                    $blueprint->string('body');
                }
            });
        }
        foreach (['one', 'two'] as $name) {
            $this->selectConsumer($name);
            $owner = app(UserSynchronizer::class)->sync(['sub' => 'actor', 'name' => 'Synthetic actor']);
            $id = 'source-'.$name;
            app(SessionRepository::class)->create(['id' => $id, 'user_id' => $owner->id, 'subject' => 'actor', 'sid' => 'central-'.$name,
                'token_vault' => app(IdentityVault::class)->seal(['access_token' => 'synthetic', 'expires_at' => time() + 300], 'session:'.$id),
                'selection' => ['selected' => true], 'context_version' => 2, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addHour()]);
            $key = ['binding_hash' => app(IdentityConfig::class)->bindingHash(), 'resource_id' => 'same-resource'];
            DB::table('p12_resources')->insert([...$key, 'label' => 'Synthetic workspace', 'version' => 'r1']);
            DB::table('p12_memberships')->insert([...$key, 'actor' => 'actor', 'organization_id' => null, 'role_id' => null, 'version' => 'm1']);
            DB::table('p12_documents')->insert([...$key, 'owner' => 'actor', 'body' => 'original']);
            $request = $this->requestFor($name, 2);
            app(ApplicationContextManager::class)->select($request);
        }
    }

    protected function tearDownInteractsWithMigrations(): void
    {
        if ($this->contenderInput !== null) {
            $this->removeFixtureDirectories();

            return;
        }
        // Stop every child before rolling back the blocker and dropping only this test's tables.
        foreach ($this->workers as [$process, $directory]) {
            $process->stop(0);
            foreach (['input.json', 'phase', 'result.json', 'failure.json'] as $file) {
                if (is_file($directory.'/'.$file)) {
                    unlink($directory.'/'.$file);
                }
            }
            rmdir($directory);
        }
        if ($this->app) {
            $blocker = DB::connection('qualification_blocker');
            while ($blocker->transactionLevel() > 0) {
                $blocker->rollBack();
            }
            foreach (['p12_outbox', 'p12_audit', 'p12_attempts', 'p12_documents', 'p12_memberships', 'p12_resources'] as $table) {
                Schema::dropIfExists($table);
            }
        }
        $this->tearDownPostgresMigrations();
        $this->removeFixtureDirectories();
    }

    private function removeFixtureDirectories(): void
    {
        foreach ($this->fixtureDirectories as $directory) {
            $this->app['files']->deleteDirectory($directory);
        }
    }

    public static function membershipChanges(): array
    {
        return ['membership revision' => ['version'], 'membership removal' => ['removal']];
    }

    #[DataProvider('membershipChanges')]
    public function test_membership_wait_refuses_stale_context_and_rolls_back_without_affecting_another_binding(string $change): void
    {
        $request = $this->requestFor('one');
        $binding = app(IdentityConfig::class)->bindingHash();
        $source = app(SessionRepository::class)->find('source-one');
        self::assertNotNull($source);
        $remembered = $source->application_context;
        self::assertSame('r1:m1', $remembered['descriptor']['version']);
        $blocker = DB::connection('qualification_blocker');
        $blocker->beginTransaction();
        $membership = $blocker->table('p12_memberships')->where('binding_hash', $binding)->where('resource_id', 'same-resource')->where('actor', 'actor');
        self::assertNotNull($membership->lockForUpdate()->first());
        $contender = $this->startContextContender('one');
        $this->assertMembershipWait($contender);

        // Physical resource ownership is binding-scoped: identical IDs are different host rows.
        $control = $this->startContextContender('two');
        self::assertSame(['outcome' => 'committed', 'mutation_entered' => true, 'eligible' => true, 'policy_passed' => true], $this->finishContextContender($control));
        $this->assertMembershipWait($contender);
        $this->requestFor('two');
        $otherBinding = app(IdentityConfig::class)->bindingHash();
        self::assertNotSame($binding, $otherBinding);
        $this->assertDomainEffects($otherBinding, 'committed', 1);
        self::assertSame('r1:m1', app(ApplicationContextManager::class)->current(app('request'))->version);
        self::assertSame(3, app(SessionRepository::class)->find('source-two')->context_version);

        // Change only after observing the actual child wait; commit releases that exact membership.
        self::assertSame(1, $change === 'version' ? $membership->update(['version' => 'm2']) : $membership->delete());
        $blocker->commit();
        self::assertSame(['outcome' => 'application_context_unavailable', 'mutation_entered' => true, 'eligible' => false, 'policy_passed' => false], $this->finishContextContender($contender));
        $this->assertDomainEffects($binding, 'original', 0);
        self::assertSame($change === 'version' ? 'm2' : null, DB::table('p12_memberships')->where('binding_hash', $binding)->value('version'));
        $request = $this->requestFor('one');
        $source = app(SessionRepository::class)->find('source-one');
        self::assertSame(3, $source->context_version);
        self::assertSame($remembered, $source->application_context, 'Refused transaction must not commit context cleanup');
        self::assertNull(app(ApplicationContextManager::class)->current($request));
        self::assertSame(4, app(SessionRepository::class)->find('source-one')->context_version);
        self::assertNull(app(SessionRepository::class)->find('source-one')->application_context);
        $this->requestFor('two');
        self::assertSame('same-resource', app(ApplicationContextManager::class)->current(app('request'))->resourceId);
        $this->assertDomainEffects($otherBinding, 'committed', 1);
    }

    private function requestFor(string $name, int $version = 3): Request
    {
        $this->selectConsumer($name);
        $origin = $name === 'one' ? 'https://consumer.test' : 'https://second.test';
        $request = Request::create($origin.'/auth/application-context', 'POST', ['context_version' => $version, 'kind' => 'workspace', 'resourceId' => 'same-resource']);
        $store = new Store('context_'.$name, new ArraySessionHandler(120));
        $store->start();
        $store->regenerateToken();
        $store->put('identity.session', 'source-'.$name);
        $request->setLaravelSession($store);
        $request->headers->set('Origin', $origin);
        $request->merge(['_token' => $store->token()]);
        $this->bindRequest($request);

        return $request;
    }

    private function assertDomainEffects(string $binding, string $body, int $count): void
    {
        self::assertSame($body, DB::table('p12_documents')->where('binding_hash', $binding)->where('resource_id', 'same-resource')->value('body'));
        foreach (['p12_attempts', 'p12_audit', 'p12_outbox'] as $table) {
            self::assertSame($count, DB::table($table)->where('binding_hash', $binding)->where('resource_id', 'same-resource')->count(), $table.' must share the runner transaction');
        }
    }

    private function startContextContender(string $consumer): array
    {
        $directory = sys_get_temp_dir().'/identity-pg-context-'.bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        $label = 'identity-context-'.bin2hex(random_bytes(8));
        $input = ['connection' => [...config('database.connections.qualification'), 'application_name' => $label], 'consumer' => $consumer, 'directory' => $directory];
        $mask = umask(0077);
        try {
            file_put_contents($directory.'/input.json', json_encode($input, JSON_THROW_ON_ERROR));
        } finally {
            umask($mask);
        }
        $process = new Process([PHP_BINARY, __DIR__.'/application-context-contender.php', $directory.'/input.json'], dirname(__DIR__, 2), timeout: 15);
        $this->workers[] = [$process, $directory];
        $process->start();

        return [$process, $directory, $label];
    }

    private function assertMembershipWait(array $contender): void
    {
        [$process, $directory, $label] = $contender;
        $deadline = microtime(true) + 3;
        do {
            $activity = DB::connection('qualification_observer')->table('pg_stat_activity')->where('application_name', $label)->first(['pid', 'state', 'wait_event_type']);
            if ($activity?->state === 'active' && $activity->wait_event_type === 'Lock' && is_file($directory.'/phase') && file_get_contents($directory.'/phase') === 'resource_locked') {
                self::assertGreaterThan(0, $activity->pid);
                self::assertTrue($process->isRunning());

                return;
            }
            usleep(10000);
        } while ($process->isRunning() && microtime(true) < $deadline);
        self::fail('The separate runner must wait on PostgreSQL membership lock after acquiring its resource lock');
    }

    private function finishContextContender(array $contender): array
    {
        [$process, $directory] = $contender;
        self::assertSame(0, $process->wait(), 'Context contender failed; output is intentionally private');
        self::assertFileExists($directory.'/result.json');

        return json_decode(file_get_contents($directory.'/result.json'), true, flags: JSON_THROW_ON_ERROR);
    }

    /** Dedicated executable helper boots the package fixture without migrations or fixture writes. */
    public function runContextContender(array $input): array
    {
        $this->contenderInput = $input;
        $this->setUp();
        try {
            $request = $this->requestFor($input['consumer']);
            $key = ['binding_hash' => app(IdentityConfig::class)->bindingHash(), 'resource_id' => 'same-resource'];
            $result = ['outcome' => 'committed', 'mutation_entered' => false, 'eligible' => false, 'policy_passed' => false];
            try {
                app(OrdinaryActionRunner::class)->run($request, function () use ($input, $key) {
                    // A real provisional write makes rollback observable even when eligibility refuses.
                    DB::table('p12_attempts')->insert($key);
                    DB::table('p12_resources')->where($key)->lockForUpdate()->firstOrFail();
                    file_put_contents($input['directory'].'/phase', 'resource_locked');
                    PostgresWorkspaceFixture::memberships($key, 'actor', [])->lockForUpdate()->first();

                    return DB::table('p12_documents')->where($key)->lockForUpdate()->firstOrFail();
                }, function ($document, Principal $principal) use ($request, $key, &$result): void {
                    $result['mutation_entered'] = true;
                    $context = app(ApplicationContextManager::class)->assertEligible($request, $principal);
                    $result['eligible'] = true;
                    // Context narrows the resource; central permission AND local owner policy still govern.
                    if (! $principal->hasPermission('documents.update') || $document->owner !== $principal->subject()
                        || $context->resourceId !== $document->resource_id || $context->consumerBinding !== $document->binding_hash) {
                        throw new IdentityException('access_denied', 403);
                    }
                    $result['policy_passed'] = true;
                    DB::table('p12_documents')->where($key)->update(['body' => 'committed']);
                    DB::table('p12_audit')->insert($key);
                    DB::table('p12_outbox')->insert($key);
                });
            } catch (IdentityException $error) {
                $result['outcome'] = $error->errorCode;
            }

            return $result;
        } finally {
            $this->tearDown();
        }
    }
}

/** Host fixture: binding-scoped physical rows, resource -> membership -> document -> source order. */
class PostgresWorkspaceFixture implements ApplicationContextProvider
{
    public function choices(ApplicationContextScope $scope): iterable
    {
        if ($resource = $this->resolve($scope, 'same-resource', false)) {
            yield $resource;
        }
    }

    public static function memberships(array $key, string $actor, array $selection): Builder
    {
        return DB::table('p12_memberships')->where($key)->where('actor', $actor)
            ->where('organization_id', $selection['organizationId'] ?? null)->where('role_id', $selection['roleId'] ?? null);
    }

    public function resolve(ApplicationContextScope $scope, string $resourceId, bool $forUpdate): ?ApplicationContextResource
    {
        $key = ['binding_hash' => $scope->bindingHash, 'resource_id' => $resourceId];
        $resources = DB::table('p12_resources')->where($key);
        $memberships = self::memberships($key, $scope->actorSubject, $scope->selection);
        $resource = ($forUpdate ? $resources->lockForUpdate() : $resources)->first();
        $membership = ($forUpdate ? $memberships->lockForUpdate() : $memberships)->first();
        if (! $resource || ! $membership) {
            return null;
        }

        return new ApplicationContextResource($resourceId, $resource->label, $resource->version.':'.$membership->version, CarbonImmutable::now()->addMinutes(5));
    }
}
