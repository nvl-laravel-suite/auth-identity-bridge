<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Sync;

use IdentityPlatform\Laravel\Authorization\Contract;
use IdentityPlatform\Laravel\Support\ConsumerGraph;

/** Bind one instance in the host container; CLI input selects only a registered name.
 * @api
 */
final class UserImportSourceRegistry
{
    /** @var array<string, class-string<UserImportSource>> */
    private array $sources = [];

    public function register(string $name, string $class): void
    {
        Contract::require(preg_match('/^[a-z][a-z0-9_-]{0,63}$/D', $name) === 1 && is_subclass_of($class, UserImportSource::class) && ! isset($this->sources[$name]), 'user_import_source_invalid', 422);
        $this->sources[$name] = $class;
    }

    public function resolve(string $name, ConsumerGraph $graph): UserImportSource
    {
        Contract::require(isset($this->sources[$name]), 'user_import_source_unknown', 422);
        $source = $graph->make($this->sources[$name]);
        Contract::require($source instanceof UserImportSource, 'user_import_source_invalid', 422);

        return $source;
    }
}
