<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

use Illuminate\Contracts\Container\Container;

/** Never apply this consumer's lifetime to unowned rows or another binding's files. */
final readonly class SessionGarbageCollector
{
    public function __construct(private Container $app, private ConsumerContext $context, private bool $defaultNamespace) {}

    public function collect(int $lifetime): int
    {
        return match ($this->context->value('session.driver')) {
            'database' => $this->database($lifetime),
            'file' => $this->files($lifetime),
            default => 0, // Cache backends expire individual keys; unknown drivers own retention.
        };
    }

    private function owns(string $id, string $payload): bool
    {
        $namespace = 'identity:'.$this->context->bindingHash().':';
        $keyMatches = $this->defaultNamespace ? ! str_starts_with($id, 'identity:') : str_starts_with($id, $namespace);

        return $keyMatches && str_starts_with($payload, 'identity-session.v1:'.$this->context->bindingHash()."\n");
    }

    private function database(int $lifetime): int
    {
        $table = $this->context->value('session.table');
        ContextDefinition::require($table !== null);
        $query = $this->app->make('db')->connection($this->context->value('session.connection'))->table($table);
        $deleted = 0;
        (clone $query)->where('last_activity', '<=', time() - $lifetime)->orderBy('id')->chunkById(100, function ($rows) use ($query, &$deleted): void {
            foreach ($rows as $row) {
                if (! is_string($row->id) || ! is_string($row->payload)) {
                    continue;
                }
                $payload = base64_decode($row->payload, true);
                if ($payload === false || ! $this->owns($row->id, $payload)) {
                    continue;
                }
                // A concurrent refresh or ownership change must survive this sweep.
                $deleted += (clone $query)->where('id', $row->id)->where('last_activity', $row->last_activity)->where('payload', $row->payload)->delete();
            }
        });

        return $deleted;
    }

    private function files(int $lifetime): int
    {
        $deleted = 0;
        $directory = $this->context->value('session.files');
        ContextDefinition::require($directory !== null);
        foreach ($this->app->make('files')->files($directory) as $file) {
            if ($file->isLink() || $file->getMTime() > time() - $lifetime) {
                continue;
            }
            $handle = @fopen($file->getPathname(), 'r+');
            if ($handle === false) {
                continue;
            }
            try {
                if (! flock($handle, LOCK_EX)) {
                    continue;
                }
                $stat = fstat($handle);
                $payload = stream_get_contents($handle);
                if ($stat !== false && $stat['mtime'] <= time() - $lifetime && is_string($payload) && $this->owns($file->getFilename(), $payload) && unlink($file->getPathname())) {
                    $deleted++;
                }
            } finally {
                flock($handle, LOCK_UN);
                fclose($handle);
            }
        }

        return $deleted;
    }
}
