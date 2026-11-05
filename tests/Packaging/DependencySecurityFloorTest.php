<?php

declare(strict_types=1);

use Composer\Semver\Semver;

it('excludes affected Symfony versions from standalone Identity installations', function (string $section, string $dependency, string $version, bool $accepted): void {
    $manifest = json_decode(file_get_contents(dirname(__DIR__, 2).'/composer.json'), true, flags: JSON_THROW_ON_ERROR);
    $constraint = $manifest[$section][$dependency] ?? '*';
    $allowed = Semver::satisfies($version, $constraint);

    if ($section === 'conflict') {
        $allowed = ! isset($manifest[$section][$dependency]) || ! $allowed;
    }

    expect($allowed)->toBe($accepted);
})->with([
    'HTTP Foundation runtime' => ['require', 'symfony/http-foundation'],
    'HTTP Kernel conflict' => ['conflict', 'symfony/http-kernel'],
    'Routing conflict' => ['conflict', 'symfony/routing'],
])->with([
    'previous Symfony 7 floor' => ['7.4.19', false],
    'last affected Symfony 7 patch' => ['7.4.22', false],
    'previous Symfony 8 floor' => ['8.1.7', false],
    'last affected Symfony 8 patch' => ['8.1.10', false],
    'patched Symfony 7 floor' => ['7.4.23', true],
    'later Symfony 7 patch' => ['7.4.24', true],
    'patched Symfony 8 floor' => ['8.1.11', true],
    'later Symfony 8 minor' => ['8.2.0', true],
]);
