<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\ApplicationContext;

use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Support\IdentityConfig;

/** Exact server-owned ordinary identity; contains no token, model or permission ledger. */
final readonly class ApplicationContextScope
{
    public function __construct(public string $consumer, public string $bindingHash, public string $sourceId, public string $sourceSid, public string $actorSubject, public string $userId, public array $selection) {}

    public static function from(IdentityConfig $config, IdentitySession $row): self
    {
        return new self($config->context()->name(), $config->bindingHash(), $row->id, $row->sid, $row->subject, $row->user_id, $row->selection);
    }
}
