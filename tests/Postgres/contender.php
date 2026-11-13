<?php

declare(strict_types=1);

use Illuminate\Database\Capsule\Manager;

require dirname(__DIR__).'/bootstrap.php';

try {
    $input = json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR);
    if (! preg_match('/\Aq_[a-f0-9]{8}_\z/', $input['connection']['prefix']) || ! in_array($input['connection']['host'], ['127.0.0.1', 'localhost'], true)) {
        throw new RuntimeException('invalid_qualification_scope');
    }
    $database = new Manager;
    $database->addConnection($input['connection']);
    $changed = $database->getConnection()->table('identity_sessions')->where('id', $input['session'])->increment('context_version');
    file_put_contents($input['result'], json_encode(['updated' => $changed], JSON_THROW_ON_ERROR));
} catch (Throwable) {
    fwrite(STDERR, "qualification_contender_failed\n");
    exit(1);
}
