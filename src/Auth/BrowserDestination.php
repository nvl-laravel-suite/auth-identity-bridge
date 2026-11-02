<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Support\ConsumerRegistry;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\SafeReturn;
use JsonSerializable;

final readonly class BrowserDestination implements JsonSerializable
{
    private function __construct(public string $kind, public string $url, public ?string $consumer = null) {}

    public static function local(mixed $path): self
    {
        return new self('local', SafeReturn::path($path));
    }

    /** Only trusted registration selects a different surface. No source proof is forwarded. */
    public static function surface(ConsumerRegistry $registry, string $consumer): self
    {
        $target = $registry->get($consumer);
        if (! $target->hasBrowser() || ! $target->value('routes.enabled')) {
            throw new IdentityException('browser_destination_unavailable', 409);
        }

        return new self('surface', (new IdentityConfig($target))->url('entry'), $target->name());
    }

    /**
     * @return array{kind: string, url: string, consumer: string|null}
     */
    public function jsonSerialize(): array
    {
        return ['kind' => $this->kind, 'url' => $this->url, 'consumer' => $this->consumer];
    }
}
