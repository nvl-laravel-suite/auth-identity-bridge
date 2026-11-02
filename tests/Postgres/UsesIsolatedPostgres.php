<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Tests\Postgres;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use RuntimeException;
use Symfony\Component\Process\Process;

/** Every test owns a random table prefix; never reset or enumerate consumer data. */
trait UsesIsolatedPostgres
{
    private ?string $qualificationPrefix = null;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        if (getenv('IDENTITY_TEST_POSTGRES_ENABLED') !== 'true' || ! getenv('IDENTITY_TEST_PG_DATABASE') || ! getenv('IDENTITY_TEST_PG_USERNAME')) {
            throw new RuntimeException('Explicit local PostgreSQL qualification configuration is required');
        }
        $host = getenv('IDENTITY_TEST_PG_HOST') ?: '127.0.0.1';
        if (! in_array($host, ['127.0.0.1', 'localhost'], true)) {
            throw new RuntimeException('This qualification uses only the explicitly supplied local PostgreSQL service');
        }
        $this->qualificationPrefix ??= 'q_'.bin2hex(random_bytes(4)).'_';
        $connection = ['driver' => 'pgsql', 'host' => $host, 'port' => getenv('IDENTITY_TEST_PG_PORT') ?: '5432',
            'database' => getenv('IDENTITY_TEST_PG_DATABASE'), 'username' => getenv('IDENTITY_TEST_PG_USERNAME'),
            'password' => getenv('IDENTITY_TEST_PG_PASSWORD') ?: '', 'charset' => 'utf8', 'prefix' => $this->qualificationPrefix,
            'search_path' => 'public', 'sslmode' => 'prefer'];
        $app['config']->set('database.connections.qualification', $connection);
        $app['config']->set('database.connections.qualification_observer', [...$connection, 'prefix' => '']);
        $app['config']->set('database.default', 'qualification');
        $app['config']->set('identity.connection', 'qualification');
    }

    protected function tearDownInteractsWithMigrations(): void
    {
        if ($this->app && $this->qualificationPrefix) {
            Schema::connection('qualification')->dropIfExists('owned_documents');
        }
        parent::tearDownInteractsWithMigrations();
        if ($this->app && $this->qualificationPrefix) {
            Schema::connection('qualification')->dropIfExists('migrations');
        }
    }

    /** Observe an actual PostgreSQL lock wait from a separate PHP worker. */
    protected function startNativeContender(string $sessionId): array
    {
        $directory = sys_get_temp_dir().'/identity-pg-'.bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        $configuration = config('database.connections.qualification');
        $label = 'identity-qualification-'.bin2hex(random_bytes(8));
        file_put_contents($directory.'/input.json', json_encode(['connection' => [...$configuration, 'application_name' => $label], 'session' => $sessionId, 'result' => $directory.'/result.json'], JSON_THROW_ON_ERROR));
        chmod($directory.'/input.json', 0600);
        $process = new Process([PHP_BINARY, __DIR__.'/contender.php', $directory.'/input.json'], dirname(__DIR__, 2), timeout: 10);
        $process->start();
        $waiting = false;
        $deadline = microtime(true) + 3;
        do {
            $waiting = DB::connection('qualification_observer')->table('pg_stat_activity')->where('application_name', $label)->value('wait_event_type') === 'Lock';
            if ($waiting || ! $process->isRunning()) {
                break;
            }
            usleep(10000);
        } while (microtime(true) < $deadline);
        if (! $waiting) {
            $process->stop(0);
            $this->cleanupContender($directory);
        }
        $this->assertTrue($waiting, 'The competing PostgreSQL worker must wait on the native session fence');

        return [$process, $directory];
    }

    protected function finishNativeContender(array $contender): void
    {
        [$process, $directory] = $contender;
        try {
            $this->assertSame(0, $process->wait(), 'The contender should complete only after the runner commits');
            $this->assertSame(['updated' => 1], json_decode(file_get_contents($directory.'/result.json'), true, flags: JSON_THROW_ON_ERROR));
        } finally {
            $process->stop(0);
            $this->cleanupContender($directory);
        }
    }

    private function cleanupContender(string $directory): void
    {
        foreach (glob($directory.'/*') as $file) {
            unlink($file);
        }
        rmdir($directory);
    }
}
