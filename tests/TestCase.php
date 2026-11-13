<?php

namespace IdentityPlatform\Laravel\Tests;

require_once __DIR__.'/Support/NamedConfigurationFixture.php';

use IdentityPlatform\Laravel\Authorization\IdentityAccess;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\IdentityServiceProvider;
use IdentityPlatform\Laravel\Support\ConsumerGraph;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\ConsumerSessionManager;
use IdentityPlatform\Laravel\Support\ServiceTargetRegistry;
use IdentityPlatform\Laravel\Tests\Support\FixtureNativeFactory;
use IdentityPlatform\Laravel\Tests\Support\NamedConfigurationFixture;
use Illuminate\Http\Request;
use Orchestra\Testbench\Database\MigrateProcessor;
use Orchestra\Testbench\TestCase as Orchestra;
use PDO;

abstract class TestCase extends Orchestra
{
    use NamedConfigurationFixture;

    private static ?string $sqliteSchemaSql = null;

    private static bool $tempDirectoriesReady = false;

    private static string $packageCacheDirectory = '';

    private static string $sessionFilesDirectory = '';

    protected function getPackageProviders($app): array
    {
        return [IdentityServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        if (! self::$tempDirectoriesReady) {
            $ownerPid = getmypid();
            self::$packageCacheDirectory = sys_get_temp_dir().'/identity-package-'.$ownerPid;
            self::$sessionFilesDirectory = sys_get_temp_dir().'/identity-sessions-'.$ownerPid;
            $app['files']->ensureDirectoryExists(self::$packageCacheDirectory);
            $app['files']->ensureDirectoryExists(self::$sessionFilesDirectory);
            $files = $app['files'];
            $cacheDir = self::$packageCacheDirectory;
            $sessionDir = self::$sessionFilesDirectory;
            register_shutdown_function(static function () use ($files, $cacheDir, $sessionDir, $ownerPid): void {
                if (getmypid() === $ownerPid) {
                    $files->deleteDirectory($cacheDir);
                    $files->deleteDirectory($sessionDir);
                }
            });
            self::$tempDirectoriesReady = true;
        }
        $app['files']->ensureDirectoryExists(self::$packageCacheDirectory);
        $app['files']->ensureDirectoryExists(self::$sessionFilesDirectory);

        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('hashing.bcrypt.rounds', 4);
        $app['config']->set('database.default', 'sqlite');
        $app['config']->set('database.connections.sqlite', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true]);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('cache.stores.identity_tests', ['driver' => 'file', 'path' => self::$packageCacheDirectory]);
        $app['config']->set('session.driver', 'array');
        $definition = $this->definition();
        $definition['consumers']['one']['users']['model'] = null;
        $definition['consumers']['one']['users']['fields'] = [];
        $definition['consumers']['one']['browser']['client_secret'] = 'secret';
        $definition['consumers']['one']['resource'] = ['client_id' => 'verifier-1', 'client_secret' => 'resource-secret'];
        $definition['consumers']['one']['session']['driver'] = 'file';
        $definition['consumers']['one']['session']['files'] = self::$sessionFilesDirectory;
        $definition['consumers']['one']['session']['connection'] = null;
        $definition['consumers']['one']['session']['cookie'] = $app['config']->get('session.cookie', 'identity_session');
        $definition['consumers']['one']['session']['encrypt'] = false;
        $definition['consumers']['one']['lock_store'] = 'identity_tests';
        $definition['consumers']['one']['delegation'] = ['routes' => [], 'operations' => []];
        $definition['service_targets']['reports'] = ['origin' => 'https://identity.test', 'application_id' => 'app-1', 'base_url' => 'https://consumer.test/api', 'client_id' => 'worker-1', 'client_secret' => 'service-secret', 'scopes' => ['documents.read'], 'cache_store' => 'array', 'http' => ['ca_bundle' => null, 'max_response_bytes' => 131072]];
        $app['config']->set('identity', $definition);
    }

    protected function tearDown(): void
    {
        $files = $this->app?->bound('files') ? $this->app['files'] : null;
        parent::tearDown();
        if ($files !== null) {
            foreach ([self::$packageCacheDirectory, self::$sessionFilesDirectory] as $directory) {
                if ($directory !== '' && is_dir($directory) && count(scandir($directory) ?: []) > 2) {
                    $files->cleanDirectory($directory);
                }
            }
        }
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->selectConsumer();
        config(['session' => $this->graph()->context->sessionSettings()]);
        $this->app->instance('session', new ConsumerSessionManager($this->app, $this->graph()->context, true));
    }

    public function withSession(array $data)
    {
        parent::withSession($data);
        $store = $this->app['session']->driver();
        $store->save();

        return $this->withCookie($store->getName(), $store->getId());
    }

    protected function selectConsumer(string $name = 'one'): void
    {
        $this->app->forgetInstance(ConsumerRegistry::class);
        $this->app->forgetInstance(Identity::class);
        $this->app->forgetInstance(ServiceTargetRegistry::class);
        $this->app->instance(ConsumerGraph::class, $this->app->make(Identity::class)->consumer($name, $this->app['request']));
    }

    protected function configure(array $values): void
    {
        config($values);
        if (array_any(array_keys($values), fn ($key) => str_starts_with($key, 'identity.') || str_starts_with($key, 'database.'))) {
            $this->selectConsumer();
        }
    }

    protected function bindRequest(Request $request): void
    {
        $this->app->instance('request', $request);
        $graph = $this->graph();
        $graph->instance(Request::class, $request);
        if ($graph->resolved(IdentityAccess::class)) {
            $graph->make(IdentityAccess::class)->setRequest($request);
        }
    }

    protected function nativeFactory(\Closure $factory): void
    {
        FixtureNativeFactory::$create = $factory;
        $this->configure(['identity.consumers.one.users.factory' => FixtureNativeFactory::class]);
    }

    protected function graph(): ConsumerGraph
    {
        return $this->app->make(ConsumerGraph::class);
    }

    protected function defineDatabaseMigrations(): void
    {
        $connection = $this->app['db']->connection();
        if (config('identity.connection') !== null
            || $connection->getDriverName() !== 'sqlite'
            || $connection->getDatabaseName() !== ':memory:'
            || $connection->getTablePrefix() !== '') {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

            return;
        }

        $pdo = $connection->getPdo();
        if (self::$sqliteSchemaSql !== null) {
            $pdo->exec(self::$sqliteSchemaSql);

            return;
        }

        $migrator = new MigrateProcessor($this, $this->resolvePackageMigrationsOptions(__DIR__.'/../database/migrations'));
        $migrator->up();
        $this->resetApplicationArtisanCommands($this->app);

        $statements = [];
        $objects = $pdo->query(
            "select sql from sqlite_master where sql is not null and name not like 'sqlite_%' order by case type when 'table' then 0 else 1 end, rowid",
        )->fetchAll(PDO::FETCH_COLUMN);
        foreach ($objects as $sql) {
            $statements[] = (string) $sql;
        }

        $migrations = $connection->getTablePrefix().config('database.migrations.table', 'migrations');
        foreach ($pdo->query('select id, migration, batch from "'.str_replace('"', '""', $migrations).'" order by id')->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $statements[] = sprintf(
                'insert into "%s" ("id", "migration", "batch") values (%d, %s, %d)',
                str_replace('"', '""', $migrations),
                (int) $row['id'],
                $pdo->quote((string) $row['migration']),
                (int) $row['batch'],
            );
        }

        self::$sqliteSchemaSql = implode(";\n", $statements);
    }
}
