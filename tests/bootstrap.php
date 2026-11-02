<?php

declare(strict_types=1);

$autoload = __DIR__.'/../vendor/autoload.php';
if (! is_file($autoload)) {
    $autoload = dirname(__DIR__, 4).'/vendor/autoload.php';
}
$loader = require $autoload;
$loader->addPsr4('IdentityPlatform\\Laravel\\Tests\\', __DIR__.'/');
