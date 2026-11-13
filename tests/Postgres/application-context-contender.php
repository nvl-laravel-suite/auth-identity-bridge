<?php

declare(strict_types=1);

use IdentityPlatform\Laravel\Tests\Postgres\ApplicationContextPostgresTest;
use PHPUnit\TextUI\Configuration\Builder;

require dirname(__DIR__).'/bootstrap.php';

umask(0077);
$validated = false;
try {
    $input = json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR);
    if (getenv('IDENTITY_TEST_POSTGRES_ENABLED') !== 'true'
        || ! preg_match('/\Aq_[a-f0-9]{8}_\z/', $input['connection']['prefix'])
        || ! in_array($input['connection']['host'], ['127.0.0.1', 'localhost'], true)
        || ! in_array($input['consumer'], ['one', 'two'], true)
        || realpath(dirname($argv[1])) !== realpath($input['directory'])
        || ! preg_match('/\Aidentity-pg-context-[a-f0-9]{16}\z/', basename($input['directory']))) {
        throw new RuntimeException('invalid_qualification_scope');
    }
    $validated = true;
    // Testbench's standalone fixture lifecycle still requires PHPUnit's configuration registry.
    (new Builder)->build([__FILE__, '--no-configuration']);
    $fixture = new ApplicationContextPostgresTest('test_membership_wait_refuses_stale_context_and_rolls_back_without_affecting_another_binding');
    $result = $fixture->runContextContender($input);
    file_put_contents($input['directory'].'/result.json', json_encode($result, JSON_THROW_ON_ERROR));
} catch (Throwable $error) {
    // Never emit SQL, credentials, framework exception traces or provider bodies.
    if ($validated) {
        file_put_contents($input['directory'].'/failure.json', json_encode(['exception' => $error::class, 'file' => basename($error->getFile()), 'line' => $error->getLine()], JSON_THROW_ON_ERROR));
    }
    fwrite(STDERR, "application_context_contender_failed\n");
    exit(1);
}
