<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Consumer;

use JsonSerializable;

/** Immutable receipt and original command identity; never contains changed values or audit reason. */
final readonly class ManagedCommandResult implements JsonSerializable
{
    public function __construct(public string $status, public ?array $reference = null, public ?array $receipt = null, public ?string $context = null, public ?string $refresh = null, public ?ManagedFailure $error = null) {}

    public function jsonSerialize(): array
    {
        return array_filter(['status' => $this->status, 'reference' => $this->reference, 'receipt' => $this->receipt, 'context' => $this->context, 'refresh' => $this->refresh, 'error' => $this->error], fn ($value) => $value !== null);
    }
}
