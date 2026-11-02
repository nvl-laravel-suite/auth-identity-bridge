<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Console;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Identity;
use IdentityPlatform\Laravel\Support\ExecutionPolicy;
use IdentityPlatform\Laravel\Sync\ImportRunner;
use IdentityPlatform\Laravel\Sync\UserImportSourceRegistry;
use Illuminate\Console\Command;
use Throwable;

class ImportIdentityUsers extends Command
{
    protected $signature = 'identity:users-import {--consumer= : Explicit registered consumer} {--source= : Trusted registered source name} {--dry-run : Read-only local checks; remote checks remain unverified} {--resume= : Existing run ID} {--limit=100 : Entries per batch, 1..100} {--max-pages=1000 : Bounded pages per invocation, 1..10000}';

    protected $description = 'Synchronously import explicitly associated native users with nonsecret resumable checkpoints';

    public function handle(Identity $identity, UserImportSourceRegistry $sources): int
    {
        try {
            app(ExecutionPolicy::class)->assertOutboundAllowed();
            $consumer = $this->option('consumer');
            $source = $this->option('source');
            if (! is_string($consumer) || $consumer === '') {
                throw new IdentityException('consumer_selection_required');
            }
            if (! is_string($source) || $source === '') {
                throw new IdentityException('user_import_source_unknown');
            }
            foreach (['limit', 'max-pages'] as $key) {
                if (! is_string($this->option($key)) || ! ctype_digit($this->option($key))) {
                    throw new IdentityException('user_import_limit_invalid');
                }
            }
            $graph = $identity->consumer($consumer);
            $result = $graph->make(ImportRunner::class)->run($source, $sources->resolve($source, $graph), $this->option('resume'), (bool) $this->option('dry-run'), (int) $this->option('limit'), (int) $this->option('max-pages'));
            $this->line(json_encode($result, JSON_THROW_ON_ERROR));

            return $result['completed'] || (($result['dryRun'] ?? false) && $result['exhausted']) ? self::SUCCESS : self::FAILURE;
        } catch (Throwable $error) {
            $this->error($error instanceof IdentityException && in_array($error->errorCode, ['consumer_selection_required', 'unknown_consumer'], true) ? $error->errorCode : ImportRunner::safeCode($error));

            return self::FAILURE;
        }
    }
}
